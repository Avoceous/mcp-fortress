# MCP-Fortress — by Avoceous (https://github.com/Avoceous) | MIT License
"""
Core data models for MCP-Fortress.
All stdlib — zero external dependencies.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SecurityAction(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ALERT = "alert"              # Allow but raise alert
    REQUIRE_APPROVAL = "require_approval"  # Hold for human review
    REDACT = "redact"            # Allow with output redaction


class AlertSeverity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ToolCall:
    """Represents a single MCP tool invocation."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    tool_name: str = ""
    tool_class: Optional[str] = None       # e.g. "fs_read", "shell_exec", "http_client"
    arguments: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    raw_request: Optional[Dict[str, Any]] = None

    def arg_values_as_strings(self) -> List[str]:
        """Flatten all argument values to strings for pattern matching."""
        result = []
        def _flatten(obj: Any):
            if isinstance(obj, str):
                result.append(obj)
            elif isinstance(obj, dict):
                for v in obj.values():
                    _flatten(v)
            elif isinstance(obj, list):
                for item in obj:
                    _flatten(item)
            else:
                result.append(str(obj))
        _flatten(self.arguments)
        return result


@dataclass
class ToolManifest:
    """Represents a registered MCP tool's metadata."""
    name: str
    description: str
    input_schema: Dict[str, Any] = field(default_factory=dict)
    tool_class: Optional[str] = None
    destructiveness: int = 0           # 0-10 scale
    external_network: bool = False     # Can reach external network?
    data_scope: str = "local"          # "local" | "session" | "global" | "external"
    reversible: bool = True
    registered_at: float = field(default_factory=time.time)
    integrity_hash: Optional[str] = None
    integrity_signature: Optional[str] = None
    last_verified: Optional[float] = None
    trusted: bool = False


@dataclass
class SecurityDecision:
    """The result of running a ToolCall through the security pipeline."""
    call_id: str
    action: SecurityAction
    reason: str
    rule_name: Optional[str] = None
    blast_radius_score: Optional[int] = None  # 0-100
    alerts: List["Alert"] = field(default_factory=list)
    redacted_output: Optional[str] = None
    approval_request_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    duration_ms: float = 0.0

    @property
    def is_allowed(self) -> bool:
        return self.action in (SecurityAction.ALLOW, SecurityAction.ALERT, SecurityAction.REDACT)

    @property
    def requires_hold(self) -> bool:
        return self.action == SecurityAction.REQUIRE_APPROVAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "call_id": self.call_id,
            "action": self.action.value,
            "reason": self.reason,
            "rule_name": self.rule_name,
            "blast_radius_score": self.blast_radius_score,
            "alerts": [a.to_dict() for a in self.alerts],
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms,
        }


@dataclass
class Alert:
    """A security alert raised during evaluation."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    severity: AlertSeverity = AlertSeverity.MEDIUM
    title: str = ""
    description: str = ""
    detector: str = ""           # Which detector raised this
    tool_call_id: Optional[str] = None
    session_id: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    mitre_attack_id: Optional[str] = None  # e.g. "T1560" (Data Staged)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "detector": self.detector,
            "tool_call_id": self.tool_call_id,
            "session_id": self.session_id,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "mitre_attack_id": self.mitre_attack_id,
        }


@dataclass
class SessionContext:
    """Tracks the history and state of an agent session."""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: Optional[str] = None
    source_ip: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    call_history: List[ToolCall] = field(default_factory=list)
    alert_history: List[Alert] = field(default_factory=list)
    total_calls: int = 0
    blocked_calls: int = 0
    risk_score: float = 0.0         # Cumulative session risk 0.0-1.0
    tags: List[str] = field(default_factory=list)  # e.g. ["suspicious", "exfil_attempt"]

    def add_call(self, call: ToolCall):
        self.call_history.append(call)
        self.total_calls += 1
        self.last_seen = time.time()
        # Keep only last 500 calls in memory
        if len(self.call_history) > 500:
            self.call_history = self.call_history[-500:]

    def recent_tool_names(self, n: int = 20) -> List[str]:
        return [c.tool_name for c in self.call_history[-n:]]

    def calls_in_last_seconds(self, seconds: float) -> int:
        cutoff = time.time() - seconds
        return sum(1 for c in self.call_history if c.timestamp >= cutoff)
