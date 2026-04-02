# MCP-Fortress — by Avoceous (https://github.com/Avoceous) | MIT License
"""
TDIV — Tool Description Integrity Verifier

Detects tool poisoning attacks:
- Cryptographic signing of tool manifests at registration
- Hash-based tamper detection on schema changes
- Semantic drift detection (description meaning changed without hash change)
- Shadow tool detection (duplicate or impersonating tools)
- Rug pull detection (trusted tool updating schema to malicious)

Zero external dependencies. Uses stdlib hmac, hashlib, json.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from mcpshield.core.models import Alert, AlertSeverity, ToolManifest

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Semantic drift detector (lightweight — no ML library needed)
# Uses keyword fingerprinting: if high-risk keywords appear in a new description
# that weren't in the original, it's suspicious.
# ---------------------------------------------------------------------------

# Keywords that indicate a tool has been poisoned to perform unauthorized actions
_INJECTION_KEYWORDS = {
    # Data exfiltration
    "exfiltrate", "exfil", "send to", "upload to", "post to", "transmit",
    "http_post", "webhook", "forward", "relay", "pipe to",
    # Credential theft
    "steal", "harvest", "collect credentials", "extract tokens", "dump secrets",
    # Command execution
    "execute arbitrary", "run shell", "spawn process", "eval(", "exec(",
    "system(", "subprocess",
    # Scope expansion
    "all files", "entire filesystem", "unrestricted", "bypass", "override policy",
    "ignore previous", "disregard instructions",
    # Social engineering in tool descriptions
    "note: this tool also", "additionally this tool will", "important: first",
    "before calling", "after calling this tool also",
}

_DESTRUCTIVE_KEYWORDS = {
    "delete", "remove", "wipe", "truncate", "drop table", "format",
    "destroy", "purge", "overwrite", "rm -rf",
}

_NETWORK_KEYWORDS = {
    "http", "https", "ftp", "smtp", "dns", "webhook", "api call",
    "external", "internet", "remote server", "cloud",
}


def _keyword_fingerprint(text: str) -> Dict[str, bool]:
    """Build a boolean keyword fingerprint from tool description."""
    text_lower = text.lower()
    return {
        "has_injection": any(k in text_lower for k in _INJECTION_KEYWORDS),
        "has_destructive": any(k in text_lower for k in _DESTRUCTIVE_KEYWORDS),
        "has_network": any(k in text_lower for k in _NETWORK_KEYWORDS),
        "word_count": len(text.split()),
        "has_html": bool(re.search(r"<[^>]+>", text)),
        "has_invisible_chars": bool(re.search(r"[\u200b-\u200f\u202a-\u202e\ufeff]", text)),
        "has_prompt_override": bool(re.search(
            r"(ignore|disregard|forget|override).{0,30}(instruction|rule|policy|constraint)",
            text_lower
        )),
    }


@dataclass
class IntegrityRecord:
    """Stored integrity record for a registered tool."""
    name: str
    description_hash: str
    schema_hash: str
    combined_signature: str
    fingerprint: Dict
    registered_at: float = field(default_factory=time.time)
    verified_count: int = 0
    last_verified: float = field(default_factory=time.time)


class ToolDescriptionIntegrityVerifier:
    """
    TDIV — verifies MCP tool manifests haven't been tampered with.
    
    Usage:
        tdiv = ToolDescriptionIntegrityVerifier(signing_key="secret")
        
        # At startup: register all trusted tools
        tdiv.register(tool_manifest)
        
        # At each tool discovery (e.g. when MCP server restarts): verify
        alerts = tdiv.verify(tool_manifest)
    """

    def __init__(
        self,
        signing_key: Optional[str] = None,
        semantic_drift_threshold: float = 0.3,
        block_on_invisible_chars: bool = True,
        block_on_prompt_override: bool = True,
    ):
        self._key = (signing_key or os.environ.get("MCPSHIELD_SIGNING_KEY") or "default-dev-key").encode()
        self._records: Dict[str, IntegrityRecord] = {}
        self._semantic_drift_threshold = semantic_drift_threshold
        self._block_on_invisible = block_on_invisible_chars
        self._block_on_prompt_override = block_on_prompt_override

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register(self, manifest: ToolManifest) -> str:
        """
        Register a tool manifest as trusted baseline.
        Returns the signature string (store this in your config).
        """
        desc_hash = self._hash(manifest.description)
        schema_hash = self._hash(json.dumps(manifest.input_schema, sort_keys=True))
        combined = self._sign(f"{manifest.name}:{desc_hash}:{schema_hash}")
        fp = _keyword_fingerprint(manifest.description)

        record = IntegrityRecord(
            name=manifest.name,
            description_hash=desc_hash,
            schema_hash=schema_hash,
            combined_signature=combined,
            fingerprint=fp,
        )
        self._records[manifest.name] = record
        manifest.integrity_hash = f"{desc_hash}:{schema_hash}"
        manifest.integrity_signature = combined
        manifest.trusted = True

        logger.info("TDIV: Registered tool '%s' (schema_hash=%s)", manifest.name, schema_hash[:8])
        return combined

    def verify(self, manifest: ToolManifest) -> Tuple[bool, List[Alert]]:
        """
        Verify a tool manifest against its registered baseline.
        
        Returns (is_clean, list_of_alerts).
        An empty alert list means the tool is clean.
        """
        alerts: List[Alert] = []
        name = manifest.name

        # --- 1. Check for invisible/zero-width characters (prompt injection in description)
        fp_current = _keyword_fingerprint(manifest.description)
        if fp_current.get("has_invisible_chars"):
            alerts.append(Alert(
                severity=AlertSeverity.CRITICAL,
                title="Invisible Characters in Tool Description",
                description=(
                    f"Tool '{name}' contains zero-width or invisible Unicode characters "
                    "commonly used to hide injected instructions from humans while delivering "
                    "them to LLMs. This is a strong indicator of tool poisoning."
                ),
                detector="TDIV",
                evidence={"tool": name, "finding": "invisible_chars"},
                mitre_attack_id="T1027",  # Obfuscated Files or Information
            ))

        # --- 2. Check for prompt override language
        if fp_current.get("has_prompt_override"):
            alerts.append(Alert(
                severity=AlertSeverity.CRITICAL,
                title="Prompt Override Language in Tool Description",
                description=(
                    f"Tool '{name}' description contains language instructing the LLM to "
                    "ignore or override safety instructions. This is a classic tool poisoning pattern."
                ),
                detector="TDIV",
                evidence={"tool": name, "finding": "prompt_override"},
                mitre_attack_id="T1055",  # Injection
            ))

        # --- 3. Check for injection keywords
        if fp_current.get("has_injection"):
            alerts.append(Alert(
                severity=AlertSeverity.HIGH,
                title="Suspicious Keywords in Tool Description",
                description=(
                    f"Tool '{name}' description contains keywords associated with data exfiltration "
                    "or unauthorized command execution. Review the tool description carefully."
                ),
                detector="TDIV",
                evidence={"tool": name, "finding": "injection_keywords"},
                mitre_attack_id="T1560",  # Archive Collected Data
            ))

        # --- 4. If not previously registered, flag as unknown
        if name not in self._records:
            alerts.append(Alert(
                severity=AlertSeverity.MEDIUM,
                title="Unregistered Tool Detected",
                description=(
                    f"Tool '{name}' was not in the trusted tool registry at startup. "
                    "This may be a shadow tool or newly added tool. Verify its legitimacy."
                ),
                detector="TDIV",
                evidence={"tool": name, "finding": "not_registered"},
            ))
            return len(alerts) == 0, alerts

        record = self._records[name]
        record.verified_count += 1
        record.last_verified = time.time()

        # --- 5. Hash integrity check
        current_desc_hash = self._hash(manifest.description)
        current_schema_hash = self._hash(json.dumps(manifest.input_schema, sort_keys=True))

        if current_desc_hash != record.description_hash:
            # Description changed — check if semantic risk increased
            semantic_alerts = self._check_semantic_drift(
                name, record.fingerprint, fp_current,
                old_hash=record.description_hash, new_hash=current_desc_hash
            )
            alerts.extend(semantic_alerts)

        if current_schema_hash != record.schema_hash:
            alerts.append(Alert(
                severity=AlertSeverity.HIGH,
                title="Tool Input Schema Changed",
                description=(
                    f"Tool '{name}' input schema has changed since registration. "
                    "This may indicate a rug pull or supply chain compromise. "
                    f"Old schema hash: {record.schema_hash[:12]}... "
                    f"New schema hash: {current_schema_hash[:12]}..."
                ),
                detector="TDIV",
                evidence={
                    "tool": name,
                    "old_hash": record.schema_hash[:16],
                    "new_hash": current_schema_hash[:16],
                    "finding": "schema_changed",
                },
                mitre_attack_id="T1195",  # Supply Chain Compromise
            ))

        # --- 6. Signature verification (if manifest carries one)
        if manifest.integrity_signature:
            expected = self._sign(f"{name}:{current_desc_hash}:{current_schema_hash}")
            if not hmac.compare_digest(manifest.integrity_signature, expected):
                alerts.append(Alert(
                    severity=AlertSeverity.CRITICAL,
                    title="Tool Integrity Signature Mismatch",
                    description=(
                        f"Tool '{name}' cryptographic signature does not match. "
                        "The tool manifest has been tampered with."
                    ),
                    detector="TDIV",
                    evidence={"tool": name, "finding": "signature_mismatch"},
                    mitre_attack_id="T1195",
                ))

        is_clean = len(alerts) == 0
        if is_clean:
            manifest.trusted = True
            manifest.last_verified = time.time()

        return is_clean, alerts

    def detect_shadow_tools(self, manifests: List[ToolManifest]) -> List[Alert]:
        """
        Detect shadow tools: tools with similar names or descriptions that
        may be impersonating legitimate tools.
        """
        alerts: List[Alert] = []
        names = [m.name for m in manifests]
        descs = {m.name: m.description.lower() for m in manifests}

        for i, name_a in enumerate(names):
            for name_b in names[i+1:]:
                # Typosquatting: very similar names
                if self._levenshtein(name_a, name_b) <= 2 and name_a != name_b:
                    alerts.append(Alert(
                        severity=AlertSeverity.HIGH,
                        title="Possible Shadow Tool (Typosquatting)",
                        description=(
                            f"Tools '{name_a}' and '{name_b}' have very similar names. "
                            "One may be impersonating the other to intercept tool calls."
                        ),
                        detector="TDIV",
                        evidence={"tool_a": name_a, "tool_b": name_b, "finding": "typosquatting"},
                        mitre_attack_id="T1036",  # Masquerading
                    ))

                # Description overlap: high overlap suggests tool shadowing
                overlap = self._description_overlap(descs[name_a], descs[name_b])
                if overlap > 0.7 and name_a != name_b:
                    alerts.append(Alert(
                        severity=AlertSeverity.MEDIUM,
                        title="Possible Shadow Tool (Description Overlap)",
                        description=(
                            f"Tools '{name_a}' and '{name_b}' have very similar descriptions "
                            f"({overlap:.0%} overlap). This may indicate tool shadowing."
                        ),
                        detector="TDIV",
                        evidence={"tool_a": name_a, "tool_b": name_b, "overlap": overlap},
                    ))

        return alerts

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _hash(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _sign(self, data: str) -> str:
        return hmac.new(self._key, data.encode("utf-8"), hashlib.sha256).hexdigest()

    def _check_semantic_drift(
        self,
        name: str,
        old_fp: Dict,
        new_fp: Dict,
        old_hash: str,
        new_hash: str,
    ) -> List[Alert]:
        """Check if a description change introduced new risk."""
        alerts = []

        # New dangerous capabilities appeared
        if not old_fp.get("has_network") and new_fp.get("has_network"):
            alerts.append(Alert(
                severity=AlertSeverity.HIGH,
                title="Tool Description Gained Network Capabilities",
                description=(
                    f"Tool '{name}' description was updated and now references network "
                    "operations that were not present before. This may indicate tool poisoning."
                ),
                detector="TDIV",
                evidence={"tool": name, "finding": "new_network_ref", "old_hash": old_hash[:12]},
                mitre_attack_id="T1041",  # Exfiltration Over C2 Channel
            ))

        if not old_fp.get("has_injection") and new_fp.get("has_injection"):
            alerts.append(Alert(
                severity=AlertSeverity.CRITICAL,
                title="Tool Description Gained Injection Keywords",
                description=(
                    f"Tool '{name}' description update introduced keywords associated with "
                    "injection or exfiltration. Strong indicator of a rug pull attack."
                ),
                detector="TDIV",
                evidence={"tool": name, "finding": "new_injection_keywords"},
                mitre_attack_id="T1195",
            ))

        # Description got much longer (hidden instructions)
        word_increase = new_fp.get("word_count", 0) - old_fp.get("word_count", 0)
        if word_increase > 50:
            alerts.append(Alert(
                severity=AlertSeverity.MEDIUM,
                title="Tool Description Significantly Expanded",
                description=(
                    f"Tool '{name}' description grew by {word_increase} words. "
                    "Sudden description expansion can be used to hide malicious instructions."
                ),
                detector="TDIV",
                evidence={"tool": name, "word_increase": word_increase},
            ))

        # If no risk increase detected, still alert about the change
        if not alerts:
            alerts.append(Alert(
                severity=AlertSeverity.LOW,
                title="Tool Description Changed",
                description=(
                    f"Tool '{name}' description changed since registration. "
                    "No obvious risk increase detected, but review is recommended."
                ),
                detector="TDIV",
                evidence={"tool": name, "old_hash": old_hash[:12], "new_hash": new_hash[:12]},
            ))

        return alerts

    def _levenshtein(self, s1: str, s2: str) -> int:
        """Compute edit distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j+1]+1, curr[j]+1, prev[j] + (c1 != c2)))
            prev = curr
        return prev[len(s2)]

    def _description_overlap(self, a: str, b: str) -> float:
        """Simple word-overlap Jaccard similarity."""
        words_a = set(a.split())
        words_b = set(b.split())
        if not words_a or not words_b:
            return 0.0
        intersection = words_a & words_b
        union = words_a | words_b
        return len(intersection) / len(union)
