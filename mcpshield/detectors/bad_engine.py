# MCP-Fortress — by Avoceous (https://github.com/Avoceous) | MIT License
"""
BAD Engine — Behavioral Anomaly Detector

Detects compromised agents and malicious behavior through call-sequence analysis.

Capabilities:
- Known attack pattern matching (exfiltration, enumeration, credential harvesting)
- Velocity anomaly detection (call rate spikes)
- Forbidden call chain detection
- Sliding-window session profiling
- Risk score accumulation per session

Zero external dependencies.
"""

from __future__ import annotations

import logging
import time
from typing import Dict, List, Optional, Tuple

from mcpshield.core.models import Alert, AlertSeverity, SessionContext, ToolCall

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Known malicious call-sequence signatures
# Each entry: (pattern_name, sequence_of_tool_name_substrings, severity, mitre_id, description)
# Matching is substring-based so "read_file" matches "filesystem_read_file" etc.
# ---------------------------------------------------------------------------

KNOWN_ATTACK_SEQUENCES = [
    (
        "data_exfiltration_via_http",
        ["read", "http_post"],
        AlertSeverity.CRITICAL,
        "T1041",
        "Agent read data then immediately made an HTTP POST — classic exfiltration pattern.",
    ),
    (
        "data_exfiltration_via_encode",
        ["read", "base64", "write"],
        AlertSeverity.HIGH,
        "T1560",
        "Agent read, base64-encoded, then wrote — data staging for exfiltration.",
    ),
    (
        "filesystem_enumeration",
        ["list_dir", "list_dir", "list_dir"],
        AlertSeverity.MEDIUM,
        "T1083",
        "Rapid repeated directory listing — filesystem reconnaissance.",
    ),
    (
        "credential_harvesting",
        ["read", "search", "read"],
        AlertSeverity.HIGH,
        "T1552",
        "Agent performed read-search-read pattern consistent with credential harvesting.",
    ),
    (
        "destructive_scan",
        ["list", "delete"],
        AlertSeverity.HIGH,
        "T1485",
        "Agent listed then immediately deleted — potential destructive action.",
    ),
    (
        "shell_after_read",
        ["read", "shell"],
        AlertSeverity.CRITICAL,
        "T1059",
        "Agent read a file then executed a shell command — possible code injection.",
    ),
    (
        "env_file_access",
        ["env", "read"],
        AlertSeverity.HIGH,
        "T1552.001",
        "Agent accessed environment variables or .env files — credential theft attempt.",
    ),
    (
        "git_config_exfil",
        ["git", "read", "http"],
        AlertSeverity.HIGH,
        "T1552.004",
        "Agent accessed git configuration then made network call — SSH key theft pattern.",
    ),
    (
        "shadow_copy_access",
        ["shadow", "vss", "backup"],
        AlertSeverity.CRITICAL,
        "T1003",
        "Agent accessed shadow copies or backup utilities — credential dumping pattern.",
    ),
    (
        "token_access_and_exfil",
        ["token", "key", "http"],
        AlertSeverity.CRITICAL,
        "T1528",
        "Agent accessed authentication tokens then made a network call.",
    ),
]


# Tool class → default destructiveness score (0–10)
TOOL_DESTRUCTIVENESS = {
    "shell_exec": 9,
    "code_exec": 9,
    "delete_file": 8,
    "write_file": 6,
    "http_post": 7,
    "http_put": 7,
    "http_delete": 8,
    "db_write": 7,
    "db_drop": 10,
    "send_email": 6,
    "webhook": 7,
    "read_file": 2,
    "list_dir": 1,
    "http_get": 3,
    "db_read": 2,
}


class BehavioralAnomalyDetector:
    """
    BAD Engine: analyses ToolCall sequences within sessions to detect malicious behavior.
    
    Usage:
        bad = BehavioralAnomalyDetector()
        
        # Called on every tool invocation BEFORE passing to upstream
        alerts = bad.analyze(tool_call, session_context)
    """

    def __init__(
        self,
        max_calls_per_minute: int = 60,
        max_calls_per_second: float = 5.0,
        anomaly_sensitivity: float = 0.7,
        sequence_window: int = 10,
    ):
        self._max_cpm = max_calls_per_minute
        self._max_cps = max_calls_per_second
        self._sensitivity = anomaly_sensitivity
        self._window = sequence_window
        # Per-session baseline profiles (session_id -> profile dict)
        self._profiles: Dict[str, Dict] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, call: ToolCall, session: SessionContext) -> List[Alert]:
        """
        Analyze a tool call in context of its session.
        Returns list of alerts (empty = clean).
        """
        alerts: List[Alert] = []

        # 1. Velocity checks
        alerts.extend(self._check_velocity(call, session))

        # 2. Known attack sequence matching
        alerts.extend(self._check_sequences(call, session))

        # 3. Forbidden call chains (configurable)
        alerts.extend(self._check_forbidden_chains(call, session))

        # 4. Session risk accumulation
        if alerts:
            self._update_risk_score(session, alerts)

        return alerts

    # ------------------------------------------------------------------
    # Velocity Checks
    # ------------------------------------------------------------------

    def _check_velocity(self, call: ToolCall, session: SessionContext) -> List[Alert]:
        alerts = []

        # Calls per minute
        cpm = session.calls_in_last_seconds(60)
        if cpm > self._max_cpm:
            alerts.append(Alert(
                severity=AlertSeverity.HIGH,
                title="Abnormal Call Velocity",
                description=(
                    f"Session '{session.session_id[:8]}' made {cpm} tool calls in the last minute "
                    f"(limit: {self._max_cpm}). Possible automated attack or runaway agent."
                ),
                detector="BAD",
                tool_call_id=call.id,
                session_id=session.session_id,
                evidence={"calls_per_minute": cpm, "threshold": self._max_cpm},
                mitre_attack_id="T1499",  # Resource Exhaustion
            ))

        # Calls per second (burst detection)
        cps = session.calls_in_last_seconds(1)
        if cps > self._max_cps:
            alerts.append(Alert(
                severity=AlertSeverity.MEDIUM,
                title="Call Burst Detected",
                description=(
                    f"Session '{session.session_id[:8]}' made {cps} calls in the last second. "
                    "Burst patterns may indicate automated attack tooling."
                ),
                detector="BAD",
                tool_call_id=call.id,
                session_id=session.session_id,
                evidence={"calls_per_second": cps, "threshold": self._max_cps},
            ))

        return alerts

    # ------------------------------------------------------------------
    # Sequence Analysis
    # ------------------------------------------------------------------

    def _check_sequences(self, call: ToolCall, session: SessionContext) -> List[Alert]:
        alerts = []

        # Build recent sequence including this new call
        recent = session.recent_tool_names(self._window) + [call.tool_name]
        recent_lower = [n.lower() for n in recent]

        for pattern_name, signature, severity, mitre, description in KNOWN_ATTACK_SEQUENCES:
            if self._sequence_matches(recent_lower, [s.lower() for s in signature]):
                alerts.append(Alert(
                    severity=severity,
                    title=f"Known Attack Pattern Detected: {pattern_name.replace('_', ' ').title()}",
                    description=description,
                    detector="BAD",
                    tool_call_id=call.id,
                    session_id=session.session_id,
                    evidence={
                        "pattern": pattern_name,
                        "signature": signature,
                        "recent_calls": recent[-len(signature)-2:],
                    },
                    mitre_attack_id=mitre,
                ))

        return alerts

    def _sequence_matches(self, recent: List[str], signature: List[str]) -> bool:
        """
        Check if any subsequence of recent calls matches the attack signature.
        Uses substring matching so 'read' matches 'read_file', 'filesystem_read', etc.
        """
        if len(signature) > len(recent):
            return False

        # Sliding window
        for start in range(len(recent) - len(signature) + 1):
            window = recent[start: start + len(signature)]
            if all(sig_token in call_name for sig_token, call_name in zip(signature, window)):
                return True
        return False

    # ------------------------------------------------------------------
    # Forbidden Chain Detection
    # ------------------------------------------------------------------

    def _check_forbidden_chains(self, call: ToolCall, session: SessionContext) -> List[Alert]:
        """
        Check for patterns where a destructive tool is called after a high volume
        of reads — suggests the agent is systematically enumerating before destroying.
        """
        alerts = []
        recent = session.recent_tool_names(20)
        recent_lower = [n.lower() for n in recent]

        # If current call is destructive and there's been significant read activity
        is_destructive = any(
            d in call.tool_name.lower()
            for d in ["delete", "remove", "wipe", "drop", "truncate", "format"]
        )

        if is_destructive:
            read_count = sum(1 for n in recent_lower if "read" in n or "list" in n or "get" in n)
            if read_count >= 5:
                alerts.append(Alert(
                    severity=AlertSeverity.HIGH,
                    title="Enumerate-Then-Destroy Pattern",
                    description=(
                        f"Agent performed {read_count} read/list operations before attempting "
                        f"destructive call to '{call.tool_name}'. This is consistent with "
                        "targeted data destruction after reconnaissance."
                    ),
                    detector="BAD",
                    tool_call_id=call.id,
                    session_id=session.session_id,
                    evidence={
                        "destructive_tool": call.tool_name,
                        "preceding_reads": read_count,
                    },
                    mitre_attack_id="T1485",
                ))

        return alerts

    # ------------------------------------------------------------------
    # Session Risk Scoring
    # ------------------------------------------------------------------

    def _update_risk_score(self, session: SessionContext, new_alerts: List[Alert]):
        """Accumulate session risk score based on alert severity."""
        severity_weights = {
            AlertSeverity.INFO: 0.01,
            AlertSeverity.LOW: 0.05,
            AlertSeverity.MEDIUM: 0.10,
            AlertSeverity.HIGH: 0.20,
            AlertSeverity.CRITICAL: 0.40,
        }
        for alert in new_alerts:
            session.risk_score = min(1.0, session.risk_score + severity_weights.get(alert.severity, 0.1))
            session.alert_history.append(alert)

        # Tag high-risk sessions
        if session.risk_score >= 0.8 and "high_risk" not in session.tags:
            session.tags.append("high_risk")
            logger.warning(
                "BAD: Session %s elevated to HIGH RISK (score=%.2f)",
                session.session_id[:8], session.risk_score
            )
        elif session.risk_score >= 0.5 and "suspicious" not in session.tags:
            session.tags.append("suspicious")
