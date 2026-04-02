# MCP-Fortress — by Avoceous (https://github.com/Avoceous) | MIT License
"""
PII & Secret Scanner

Scans tool call inputs AND outputs for:
- API keys (OpenAI, AWS, GitHub, Stripe, Twilio, etc.)
- Credentials (passwords, JWT tokens, OAuth tokens)
- PII (emails, phone numbers, SSNs, credit cards)
- Internal tokens and custom patterns

Actions: redact | block | alert

Zero external dependencies — uses stdlib re only.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from mcpshield.core.models import Alert, AlertSeverity

logger = logging.getLogger(__name__)


@dataclass
class ScanMatch:
    pattern_name: str
    category: str           # "secret" | "pii" | "credential"
    severity: AlertSeverity
    redact_replacement: str = "[REDACTED]"
    mitre_attack_id: Optional[str] = None


@dataclass
class ScanResult:
    has_findings: bool
    findings: List[ScanMatch]
    redacted_text: Optional[str] = None
    alerts: List[Alert] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Pattern registry
# Each entry: (name, regex, category, severity, mitre_id)
# ---------------------------------------------------------------------------

PATTERNS: List[Tuple[str, str, str, AlertSeverity, Optional[str]]] = [
    # ---- Cloud Provider API Keys ----
    (
        "aws_access_key", r"(AKIA|ASIA|AROA|AIDA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16,22}",
        "secret", AlertSeverity.CRITICAL, "T1552.001"
    ),
    (
        "aws_secret_key", r"(?i)aws.{0,20}secret.{0,20}['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "secret", AlertSeverity.CRITICAL, "T1552.001"
    ),
    (
        "openai_api_key", r"sk-[A-Za-z0-9]{48}",
        "secret", AlertSeverity.CRITICAL, "T1552"
    ),
    (
        "anthropic_api_key", r"sk-ant-[A-Za-z0-9\-_]{90,}",
        "secret", AlertSeverity.CRITICAL, "T1552"
    ),
    (
        "github_token", r"(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36}",
        "secret", AlertSeverity.CRITICAL, "T1552"
    ),
    (
        "github_classic_token", r"['\"]?[0-9a-f]{40}['\"]?",
        "secret", AlertSeverity.MEDIUM, None  # Too noisy at HIGH — SHA1 hashes look similar
    ),
    (
        "stripe_key", r"(sk|pk|rk)_(live|test)_[A-Za-z0-9]{24,}",
        "secret", AlertSeverity.CRITICAL, "T1552"
    ),
    (
        "twilio_sid", r"AC[a-f0-9]{32}",
        "secret", AlertSeverity.HIGH, "T1552"
    ),
    (
        "google_api_key", r"AIza[0-9A-Za-z\-_]{35}",
        "secret", AlertSeverity.CRITICAL, "T1552"
    ),
    (
        "slack_token", r"xox[baprs]-([0-9a-zA-Z]{10,48})",
        "secret", AlertSeverity.CRITICAL, "T1552"
    ),
    (
        "sendgrid_key", r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
        "secret", AlertSeverity.CRITICAL, "T1552"
    ),
    (
        "npm_token", r"npm_[A-Za-z0-9]{36}",
        "secret", AlertSeverity.HIGH, "T1552"
    ),
    (
        "azure_storage_key", r"(?i)AccountKey=[A-Za-z0-9/+=]{88}",
        "secret", AlertSeverity.CRITICAL, "T1552"
    ),

    # ---- JWT Tokens ----
    (
        "jwt_token", r"ey[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*",
        "credential", AlertSeverity.HIGH, "T1528"
    ),

    # ---- Generic Credential Patterns ----
    (
        "generic_password", r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?",
        "credential", AlertSeverity.HIGH, "T1552"
    ),
    (
        "generic_secret", r"(?i)(secret|api.?key|auth.?token|access.?token)\s*[:=]\s*['\"]?([^\s'\"]{16,})['\"]?",
        "credential", AlertSeverity.HIGH, "T1552"
    ),
    (
        "private_key_header", r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "secret", AlertSeverity.CRITICAL, "T1552.004"
    ),
    (
        "certificate_header", r"-----BEGIN CERTIFICATE-----",
        "secret", AlertSeverity.MEDIUM, None
    ),

    # ---- PII ----
    (
        "email_address", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "pii", AlertSeverity.LOW, None
    ),
    (
        "credit_card", r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9][0-9])[0-9]{12})\b",
        "pii", AlertSeverity.HIGH, None
    ),
    (
        "us_ssn", r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
        "pii", AlertSeverity.HIGH, None
    ),
    (
        "us_phone", r"\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "pii", AlertSeverity.LOW, None
    ),
    (
        "ipv4_private", r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        "pii", AlertSeverity.LOW, None   # Internal IP leak
    ),
]

# Pre-compile all patterns for performance
_COMPILED = [
    (name, re.compile(pattern), category, severity, mitre)
    for name, pattern, category, severity, mitre in PATTERNS
]


class PIISecretScanner:
    """
    Scans text for secrets and PII. Call scan_text() on tool inputs/outputs.
    
    Usage:
        scanner = PIISecretScanner(action="redact")
        result = scanner.scan_text(tool_output, context="output")
        if result.has_findings:
            safe_output = result.redacted_text
    """

    def __init__(
        self,
        action: str = "redact",   # "redact" | "block" | "alert"
        scan_categories: Optional[List[str]] = None,  # None = all
        min_severity: AlertSeverity = AlertSeverity.LOW,
    ):
        self._action = action
        self._categories = set(scan_categories) if scan_categories else None
        self._min_severity = min_severity

    def scan_text(self, text: str, context: str = "unknown", call_id: Optional[str] = None) -> ScanResult:
        """Scan arbitrary text for secrets and PII."""
        if not text:
            return ScanResult(has_findings=False, findings=[])

        findings: List[ScanMatch] = []
        alerts: List[Alert] = []
        redacted = text

        for name, compiled, category, severity, mitre in _COMPILED:
            # Skip if category filter set and this category not in it
            if self._categories and category not in self._categories:
                continue
            # Skip if below minimum severity
            if severity.value not in self._severity_at_or_above(self._min_severity):
                continue

            matches = compiled.findall(text)
            if not matches:
                continue

            match_obj = ScanMatch(
                pattern_name=name,
                category=category,
                severity=severity,
                mitre_attack_id=mitre,
            )
            findings.append(match_obj)

            alerts.append(Alert(
                severity=severity,
                title=f"{'Secret' if category == 'secret' else 'Credential' if category == 'credential' else 'PII'} Detected: {name.replace('_', ' ').title()}",
                description=(
                    f"Pattern '{name}' matched in tool {context}. "
                    f"Category: {category}. Action: {self._action}."
                ),
                detector="PIIScanner",
                tool_call_id=call_id,
                evidence={"pattern": name, "category": category, "context": context},
                mitre_attack_id=mitre,
            ))

            # Redact in output
            if self._action == "redact":
                redacted = compiled.sub(f"[REDACTED:{name.upper()}]", redacted)

        has_findings = len(findings) > 0

        return ScanResult(
            has_findings=has_findings,
            findings=findings,
            redacted_text=redacted if has_findings and self._action == "redact" else None,
            alerts=alerts,
        )

    def scan_json(self, obj: Any, context: str = "unknown", call_id: Optional[str] = None) -> ScanResult:
        """Scan a JSON-serializable object by converting to string first."""
        try:
            text = json.dumps(obj)
        except (TypeError, ValueError):
            text = str(obj)
        return self.scan_text(text, context=context, call_id=call_id)

    def _severity_at_or_above(self, min_sev: AlertSeverity) -> List[str]:
        order = [s.value for s in AlertSeverity]
        idx = order.index(min_sev.value)
        return order[idx:]
