# MCP-Fortress — by Avoceous (https://github.com/Avoceous) | MIT License
"""
BRE — Blast Radius Estimator

Answers: "If this MCP tool call is malicious, how bad can the damage get?"

Scores every tool call 0–100 BEFORE execution, considering:
- Tool destructiveness class
- Data scope (local / session / global / external)
- Reversibility (can this be undone?)
- External channel access (can data leave?)
- Session risk history
- Argument analysis (path depth, target sensitivity)
- Compound risk: multiple moderate risks = higher composite score

Actions based on score:
- 0–20:  AUTO_ALLOW
- 21–59: ALLOW with audit log
- 60–89: REQUIRE_HUMAN_APPROVAL (webhook notification)
- 90–100: BLOCK automatically

Zero external dependencies.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from mcpshield.core.models import Alert, AlertSeverity, SecurityAction, SessionContext, ToolCall, ToolManifest

logger = logging.getLogger(__name__)


@dataclass
class BlastRadiusResult:
    score: int                          # 0–100
    action: SecurityAction
    factors: List[Tuple[str, int]]      # (factor_name, score_contribution)
    summary: str
    alerts: List[Alert]

    @property
    def risk_level(self) -> str:
        if self.score <= 20: return "LOW"
        if self.score <= 59: return "MEDIUM"
        if self.score <= 89: return "HIGH"
        return "CRITICAL"


# ---------------------------------------------------------------------------
# Sensitive path patterns
# ---------------------------------------------------------------------------

_SENSITIVE_PATH_PATTERNS = [
    (r"\.env$|\.env\.", "Environment file", 25),
    (r"\.aws|aws[/_]credentials|\.boto", "AWS credentials", 30),
    (r"id_rsa|id_ed25519|\.pem$|\.key$|\.p12$|\.pfx$", "Private key", 30),
    (r"\.ssh/", "SSH directory", 25),
    (r"shadow|/etc/passwd|/etc/sudoers", "System credential file", 35),
    (r"authorized_keys|known_hosts", "SSH auth file", 25),
    (r"\.git/config|\.gitconfig", "Git config (may contain credentials)", 20),
    (r"database\.yml|db\.sqlite|\.db$", "Database file", 20),
    (r"secrets?\.ya?ml|secrets?\.json|secrets?\.toml", "Secrets config", 30),
    (r"/proc/|/sys/", "Linux proc/sys filesystem", 25),
    (r"\\windows\\system32|\\winnt\\", "Windows system directory", 25),
    (r"chrome.*login data|firefox.*logins\.json", "Browser saved passwords", 35),
]

_EXTERNAL_URL_PATTERNS = [
    r"https?://(?!localhost|127\.\d+\.\d+\.\d+|::1|0\.0\.0\.0)",
    r"ftp://", r"smtp://", r"s3://", r"gs://",
]

_SENSITIVE_ARG_PATTERNS = [
    (r"(password|passwd|secret|token|api.?key|private.?key)", "Credential in argument", 20),
    (r"(sudo|su -|runas|privilege|escalat)", "Privilege escalation term", 25),
    (r"\.\./\.\.|%2e%2e", "Path traversal", 20),
    (r"(rm|del|rmdir|shutil\.rmtree|os\.remove).{0,10}(\-rf|\*|/)", "Destructive glob", 30),
    (r"(eval|exec|__import__|importlib|subprocess\.call)", "Code execution term", 30),
]


class BlastRadiusEstimator:
    """
    BRE: Scores each tool call before execution based on potential damage.
    
    Usage:
        bre = BlastRadiusEstimator()
        result = bre.estimate(call, manifest, session)
        if result.action == SecurityAction.BLOCK:
            # do not forward to upstream
    """

    def __init__(
        self,
        auto_allow_threshold: int = 20,
        approval_threshold: int = 60,
        block_threshold: int = 90,
        webhook_url: Optional[str] = None,
    ):
        self._auto_allow = auto_allow_threshold
        self._approval = approval_threshold
        self._block = block_threshold
        self._webhook = webhook_url

    def estimate(
        self,
        call: ToolCall,
        manifest: Optional[ToolManifest],
        session: Optional[SessionContext] = None,
    ) -> BlastRadiusResult:
        """
        Compute blast radius score for a tool call.
        """
        factors: List[Tuple[str, int]] = []
        alerts: List[Alert] = []

        # ------------------------------------------------------------------
        # Factor 1: Base destructiveness from manifest or tool name heuristics
        # ------------------------------------------------------------------
        base_score = self._get_base_destructiveness(call, manifest)
        if base_score > 0:
            factors.append(("base_destructiveness", base_score))

        # ------------------------------------------------------------------
        # Factor 2: Data scope
        # ------------------------------------------------------------------
        scope_score = self._score_data_scope(manifest)
        if scope_score > 0:
            factors.append(("data_scope", scope_score))

        # ------------------------------------------------------------------
        # Factor 3: Reversibility penalty
        # ------------------------------------------------------------------
        if manifest and not manifest.reversible:
            factors.append(("irreversible_action", 15))

        # ------------------------------------------------------------------
        # Factor 4: External channel access
        # ------------------------------------------------------------------
        if manifest and manifest.external_network:
            factors.append(("external_network_access", 20))
        # Also check arguments for external URLs
        ext_url_score = self._check_external_urls(call)
        if ext_url_score > 0:
            factors.append(("external_url_in_args", ext_url_score))
            alerts.append(Alert(
                severity=AlertSeverity.HIGH,
                title="External URL in Tool Arguments",
                description=(
                    f"Tool '{call.tool_name}' is being called with an external URL argument. "
                    "This may indicate an SSRF or data exfiltration attempt."
                ),
                detector="BRE",
                tool_call_id=call.id,
                session_id=call.session_id,
                evidence={"tool": call.tool_name},
                mitre_attack_id="T1190",
            ))

        # ------------------------------------------------------------------
        # Factor 5: Sensitive argument patterns
        # ------------------------------------------------------------------
        arg_score, arg_alerts = self._check_sensitive_args(call)
        if arg_score > 0:
            factors.append(("sensitive_argument_patterns", arg_score))
            alerts.extend(arg_alerts)

        # ------------------------------------------------------------------
        # Factor 6: Sensitive path targets
        # ------------------------------------------------------------------
        path_score, path_alerts = self._check_sensitive_paths(call)
        if path_score > 0:
            factors.append(("sensitive_path_target", path_score))
            alerts.extend(path_alerts)

        # ------------------------------------------------------------------
        # Factor 7: Session risk history (if session is high-risk, weight up)
        # ------------------------------------------------------------------
        if session:
            session_penalty = int(session.risk_score * 20)
            if session_penalty > 0:
                factors.append(("session_risk_history", session_penalty))

        # ------------------------------------------------------------------
        # Composite score (capped at 100)
        # ------------------------------------------------------------------
        raw_score = sum(v for _, v in factors)

        # Compound risk: if ≥3 factors each ≥10, add 10% bonus
        high_factors = sum(1 for _, v in factors if v >= 10)
        if high_factors >= 3:
            compound_bonus = min(10, raw_score // 10)
            factors.append(("compound_risk_bonus", compound_bonus))
            raw_score += compound_bonus

        score = min(100, raw_score)

        # ------------------------------------------------------------------
        # Determine action
        # ------------------------------------------------------------------
        if score >= self._block:
            action = SecurityAction.BLOCK
            summary = f"BLOCK: Blast radius score {score}/100 exceeds block threshold {self._block}."
            alerts.append(Alert(
                severity=AlertSeverity.CRITICAL,
                title="Tool Call Blocked by Blast Radius Estimator",
                description=summary,
                detector="BRE",
                tool_call_id=call.id,
                session_id=call.session_id,
                evidence={"score": score, "factors": factors},
            ))
        elif score >= self._approval:
            action = SecurityAction.REQUIRE_APPROVAL
            summary = (
                f"HOLD FOR APPROVAL: Blast radius score {score}/100. "
                f"Top risk factors: {', '.join(f for f, _ in sorted(factors, key=lambda x: -x[1])[:3])}"
            )
        elif score > self._auto_allow:
            action = SecurityAction.ALERT
            summary = f"ALLOW WITH ALERT: Blast radius score {score}/100 (medium risk)."
        else:
            action = SecurityAction.ALLOW
            summary = f"ALLOW: Blast radius score {score}/100 (low risk)."

        logger.debug("BRE: tool=%s score=%d action=%s", call.tool_name, score, action.value)

        return BlastRadiusResult(
            score=score,
            action=action,
            factors=factors,
            summary=summary,
            alerts=alerts,
        )

    # ------------------------------------------------------------------
    # Scoring helpers
    # ------------------------------------------------------------------

    def _get_base_destructiveness(self, call: ToolCall, manifest: Optional[ToolManifest]) -> int:
        if manifest:
            return manifest.destructiveness * 5  # scale 0-10 → 0-50

        # Heuristic from tool name if no manifest
        name_lower = call.tool_name.lower()
        if any(k in name_lower for k in ["delete", "remove", "wipe", "drop", "truncate", "format", "purge"]):
            return 40
        if any(k in name_lower for k in ["shell", "bash", "exec", "eval", "execute", "spawn"]):
            return 45
        if any(k in name_lower for k in ["write", "create", "update", "run"]):
            return 25
        if any(k in name_lower for k in ["post", "send", "upload", "push"]):
            return 20
        if any(k in name_lower for k in ["read", "get", "list", "fetch", "search"]):
            return 5
        return 10  # unknown

    def _score_data_scope(self, manifest: Optional[ToolManifest]) -> int:
        if not manifest:
            return 0
        scope_scores = {"local": 0, "session": 5, "global": 15, "external": 25}
        return scope_scores.get(manifest.data_scope, 10)

    def _check_external_urls(self, call: ToolCall) -> int:
        arg_strings = " ".join(call.arg_values_as_strings())
        for pattern in _EXTERNAL_URL_PATTERNS:
            if re.search(pattern, arg_strings, re.IGNORECASE):
                return 20
        return 0

    def _check_sensitive_args(self, call: ToolCall) -> Tuple[int, List[Alert]]:
        alerts = []
        max_score = 0
        arg_strings = " ".join(call.arg_values_as_strings())

        for pattern, label, score in _SENSITIVE_ARG_PATTERNS:
            if re.search(pattern, arg_strings, re.IGNORECASE):
                max_score = max(max_score, score)
                alerts.append(Alert(
                    severity=AlertSeverity.HIGH if score >= 25 else AlertSeverity.MEDIUM,
                    title=f"Suspicious Argument Pattern: {label}",
                    description=(
                        f"Tool '{call.tool_name}' arguments match pattern indicating '{label}'. "
                        "This may represent a security risk."
                    ),
                    detector="BRE",
                    tool_call_id=call.id,
                    session_id=call.session_id,
                    evidence={"pattern": pattern, "label": label},
                ))

        return max_score, alerts

    def _check_sensitive_paths(self, call: ToolCall) -> Tuple[int, List[Alert]]:
        alerts = []
        max_score = 0
        arg_strings = " ".join(call.arg_values_as_strings())

        for pattern, label, score in _SENSITIVE_PATH_PATTERNS:
            if re.search(pattern, arg_strings, re.IGNORECASE):
                max_score = max(max_score, score)
                alerts.append(Alert(
                    severity=AlertSeverity.CRITICAL if score >= 30 else AlertSeverity.HIGH,
                    title=f"Sensitive Path Access: {label}",
                    description=(
                        f"Tool '{call.tool_name}' is targeting a sensitive path: {label}. "
                        "This may indicate credential theft or system compromise."
                    ),
                    detector="BRE",
                    tool_call_id=call.id,
                    session_id=call.session_id,
                    evidence={"label": label},
                    mitre_attack_id="T1552",
                ))

        return max_score, alerts
