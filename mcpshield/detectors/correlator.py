# MCP-Fortress — by Avoceous (https://github.com/Avoceous) | MIT License
"""
CSTC — Cross-Session Threat Correlator

Detects coordinated attacks spanning multiple agent sessions:
- Slow-burn exfiltration (split across many short sessions)
- Shared attacker infrastructure (IP clustering)
- Synchronized multi-agent attacks
- Anomalous session patterns (many sessions from same source)

Zero external dependencies.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from mcpshield.core.models import Alert, AlertSeverity, SessionContext

logger = logging.getLogger(__name__)


@dataclass
class CorrelationWindow:
    """Tracks events within a rolling time window."""
    window_seconds: float
    events: List[Dict] = field(default_factory=list)

    def add(self, event: Dict):
        event["_ts"] = time.time()
        self.events.append(event)
        self._prune()

    def _prune(self):
        cutoff = time.time() - self.window_seconds
        self.events = [e for e in self.events if e["_ts"] >= cutoff]

    def count(self) -> int:
        self._prune()
        return len(self.events)

    def get_values(self, key: str) -> List:
        self._prune()
        return [e[key] for e in self.events if key in e]


class CrossSessionCorrelator:
    """
    CSTC: Correlates security events across sessions to detect coordinated attacks.
    
    Usage:
        cstc = CrossSessionCorrelator()
        
        # Call after each session update
        alerts = cstc.correlate(session, all_active_sessions)
    """

    def __init__(
        self,
        window_seconds: float = 3600.0,    # 1 hour sliding window
        alert_threshold: int = 3,          # suspicious events before alert
        ip_session_threshold: int = 5,     # max sessions per IP before alert
        high_risk_threshold: int = 2,      # max high-risk sessions per IP before alert
    ):
        self._window = window_seconds
        self._alert_threshold = alert_threshold
        self._ip_session_threshold = ip_session_threshold
        self._high_risk_threshold = high_risk_threshold

        # Correlation state
        self._ip_windows: Dict[str, CorrelationWindow] = defaultdict(
            lambda: CorrelationWindow(window_seconds)
        )
        self._global_alert_window = CorrelationWindow(window_seconds)
        self._user_windows: Dict[str, CorrelationWindow] = defaultdict(
            lambda: CorrelationWindow(window_seconds)
        )

    def correlate(
        self,
        session: SessionContext,
        all_sessions: Optional[Dict[str, SessionContext]] = None,
    ) -> List[Alert]:
        """
        Correlate this session's activity against global state.
        Returns list of correlation alerts (empty = no cross-session threats).
        """
        alerts: List[Alert] = []
        all_sessions = all_sessions or {}

        # ------------------------------------------------------------------
        # 1. IP-based session clustering
        # ------------------------------------------------------------------
        if session.source_ip:
            ip_window = self._ip_windows[session.source_ip]
            # Always record this session first
            ip_window.add({"session_id": session.session_id, "risk": session.risk_score})

            session_count = ip_window.count()
            high_risk_count = sum(
                1 for r in ip_window.get_values("risk") if r >= 0.5
            )

            if session_count >= self._ip_session_threshold:
                alerts.append(Alert(
                    severity=AlertSeverity.HIGH,
                    title="Multiple Sessions from Same IP",
                    description=(
                        f"IP {session.source_ip} has initiated {session_count} sessions "
                        f"in the last {self._window/3600:.1f} hour(s). "
                        "This may indicate automated attack tooling or session enumeration."
                    ),
                    detector="CSTC",
                    session_id=session.session_id,
                    evidence={
                        "source_ip": session.source_ip,
                        "session_count": session_count,
                        "window_hours": self._window / 3600,
                    },
                    mitre_attack_id="T1078",  # Valid Accounts
                ))

            if high_risk_count >= self._high_risk_threshold:
                alerts.append(Alert(
                    severity=AlertSeverity.CRITICAL,
                    title="Multiple High-Risk Sessions from Same IP",
                    description=(
                        f"IP {session.source_ip} has {high_risk_count} high-risk sessions. "
                        "This strongly suggests a coordinated attack from shared infrastructure."
                    ),
                    detector="CSTC",
                    session_id=session.session_id,
                    evidence={
                        "source_ip": session.source_ip,
                        "high_risk_session_count": high_risk_count,
                    },
                    mitre_attack_id="T1078",
                ))

        # ------------------------------------------------------------------
        # 2. User-based anomaly detection
        # ------------------------------------------------------------------
        if session.user_id:
            user_window = self._user_windows[session.user_id]
            user_window.add({"session_id": session.session_id, "risk": session.risk_score})

            user_sessions = user_window.count()
            if user_sessions >= self._ip_session_threshold:
                alerts.append(Alert(
                    severity=AlertSeverity.MEDIUM,
                    title="Unusual Session Volume for User",
                    description=(
                        f"User '{session.user_id}' has initiated {user_sessions} sessions "
                        f"in the last hour. This may indicate account compromise."
                    ),
                    detector="CSTC",
                    session_id=session.session_id,
                    evidence={"user_id": session.user_id, "session_count": user_sessions},
                    mitre_attack_id="T1078",
                ))

        # ------------------------------------------------------------------
        # 3. Global alert rate (spike detection)
        # ------------------------------------------------------------------
        new_alerts_in_session = len(session.alert_history)
        if new_alerts_in_session > 0:
            self._global_alert_window.add({
                "session_id": session.session_id,
                "alert_count": new_alerts_in_session,
                "severity_max": max(
                    (a.severity.value for a in session.alert_history),
                    default="info"
                ),
            })

        global_alert_count = self._global_alert_window.count()
        if global_alert_count >= self._alert_threshold * 5:
            alerts.append(Alert(
                severity=AlertSeverity.HIGH,
                title="Global Alert Rate Spike",
                description=(
                    f"The system has detected {global_alert_count} alert-generating sessions "
                    f"in the last {self._window/3600:.1f} hour(s). "
                    "This may indicate a broad scanning or probing campaign."
                ),
                detector="CSTC",
                session_id=session.session_id,
                evidence={"global_alert_sessions": global_alert_count},
                mitre_attack_id="T1595",  # Active Scanning
            ))

        # ------------------------------------------------------------------
        # 4. Slow-burn exfiltration detection
        #    Many sessions from same source, each doing a small number of reads
        # ------------------------------------------------------------------
        if session.source_ip and all_sessions:
            same_ip_sessions = [
                s for s in all_sessions.values()
                if s.source_ip == session.source_ip and s.session_id != session.session_id
            ]
            total_reads = sum(
                sum(1 for c in s.call_history if "read" in c.tool_name.lower())
                for s in same_ip_sessions
            )
            if len(same_ip_sessions) >= 2 and total_reads >= 15:
                alerts.append(Alert(
                    severity=AlertSeverity.HIGH,
                    title="Potential Slow-Burn Exfiltration",
                    description=(
                        f"IP {session.source_ip} has {len(same_ip_sessions)} sessions "
                        f"that collectively performed {total_reads} read operations. "
                        "Distributing reads across many short sessions is a known "
                        "technique to evade per-session rate limits."
                    ),
                    detector="CSTC",
                    session_id=session.session_id,
                    evidence={
                        "source_ip": session.source_ip,
                        "session_count": len(same_ip_sessions),
                        "total_reads": total_reads,
                    },
                    mitre_attack_id="T1029",  # Scheduled Transfer
                ))

        return alerts
