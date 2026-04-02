# MCP-Fortress — by Avoceous (https://github.com/Avoceous) | MIT License
"""
Policy-as-Code Firewall Engine

Evaluates tool calls against declarative YAML/JSON security rules.
Supports hot-reload, rule priority ordering, and regex argument matching.

Zero external dependencies (uses stdlib json, re, pathlib).
YAML parsing requires PyYAML if using .yaml files; falls back to JSON.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcpshield.core.models import Alert, AlertSeverity, SecurityAction, ToolCall, ToolManifest

logger = logging.getLogger(__name__)


@dataclass
class PolicyRule:
    """A single policy rule."""
    name: str
    action: SecurityAction
    description: str = ""
    priority: int = 100               # Lower = evaluated first

    # Match conditions (all specified conditions must match = AND logic)
    match_tool: Optional[str] = None           # exact tool name
    match_tool_pattern: Optional[str] = None   # regex on tool name
    match_tool_class: Optional[str] = None     # tool_class field
    match_arg_pattern: Optional[str] = None    # regex against flattened arg values
    match_blast_radius_min: Optional[int] = None
    match_session_risk_min: Optional[float] = None

    # Compiled patterns (populated at load time)
    _tool_re: Optional[re.Pattern] = field(default=None, repr=False, compare=False)
    _arg_re: Optional[re.Pattern] = field(default=None, repr=False, compare=False)

    def compile(self):
        if self.match_tool_pattern:
            self._tool_re = re.compile(self.match_tool_pattern, re.IGNORECASE)
        if self.match_arg_pattern:
            self._arg_re = re.compile(self.match_arg_pattern, re.IGNORECASE)

    def matches(
        self,
        call: ToolCall,
        manifest: Optional[ToolManifest] = None,
        blast_radius: Optional[int] = None,
        session_risk: float = 0.0,
    ) -> bool:
        """Return True if this rule applies to the given call."""

        # Tool name exact match
        if self.match_tool and call.tool_name != self.match_tool:
            return False

        # Tool name regex
        if self._tool_re and not self._tool_re.search(call.tool_name):
            return False

        # Tool class
        if self.match_tool_class:
            actual_class = manifest.tool_class if manifest else call.tool_class
            if actual_class != self.match_tool_class:
                return False

        # Argument pattern
        if self._arg_re:
            arg_text = " ".join(call.arg_values_as_strings())
            if not self._arg_re.search(arg_text):
                return False

        # Blast radius threshold
        if self.match_blast_radius_min is not None:
            if blast_radius is None or blast_radius < self.match_blast_radius_min:
                return False

        # Session risk threshold
        if self.match_session_risk_min is not None:
            if session_risk < self.match_session_risk_min:
                return False

        return True


@dataclass
class PolicyEvaluationResult:
    matched_rule: Optional[PolicyRule]
    action: SecurityAction
    reason: str
    alerts: List[Alert] = field(default_factory=list)


class PolicyFirewall:
    """
    Policy-as-Code Firewall: evaluates tool calls against YAML/JSON rules.
    
    Usage:
        fw = PolicyFirewall()
        fw.load_from_file("policy.yaml")
        result = fw.evaluate(call, manifest, blast_radius=45, session_risk=0.2)
    """

    DEFAULT_ACTION = SecurityAction.ALLOW

    def __init__(self, default_action: SecurityAction = SecurityAction.ALLOW):
        self._rules: List[PolicyRule] = []
        self._default_action = default_action
        self._policy_file: Optional[Path] = None
        self._policy_mtime: float = 0.0
        self._last_check: float = 0.0

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_from_dict(self, policy: Dict[str, Any]):
        """Load policy rules from a Python dict (parsed YAML/JSON)."""
        rules_raw = policy.get("rules", [])
        new_rules: List[PolicyRule] = []

        for r in rules_raw:
            action_str = r.get("action", "allow").upper()
            try:
                action = SecurityAction[action_str]
            except KeyError:
                logger.warning("PolicyFirewall: Unknown action '%s' in rule '%s', defaulting to ALERT", action_str, r.get("name"))
                action = SecurityAction.ALERT

            rule = PolicyRule(
                name=r.get("name", f"rule_{len(new_rules)}"),
                action=action,
                description=r.get("description", r.get("reason", "")),
                priority=r.get("priority", 100),
                match_tool=r.get("match", {}).get("tool"),
                match_tool_pattern=r.get("match", {}).get("tool_pattern"),
                match_tool_class=r.get("match", {}).get("tool_class"),
                match_arg_pattern=r.get("match", {}).get("arg_pattern"),
                match_blast_radius_min=r.get("match", {}).get("blast_radius_min"),
                match_session_risk_min=r.get("match", {}).get("session_risk_min"),
            )
            rule.compile()
            new_rules.append(rule)

        # Sort by priority (lower number = higher priority)
        new_rules.sort(key=lambda r: r.priority)
        self._rules = new_rules
        logger.info("PolicyFirewall: Loaded %d rules", len(self._rules))

    def load_from_file(self, path: str):
        """Load policy from a YAML or JSON file."""
        p = Path(path)
        if not p.exists():
            logger.warning("PolicyFirewall: Policy file not found: %s", path)
            return

        self._policy_file = p
        self._policy_mtime = p.stat().st_mtime
        content = p.read_text(encoding="utf-8")

        if path.endswith(".yaml") or path.endswith(".yml"):
            try:
                import yaml
                policy = yaml.safe_load(content)
            except ImportError:
                logger.error("PyYAML not installed. Install with: pip install pyyaml")
                return
        else:
            policy = json.loads(content)

        self.load_from_dict(policy)

    def maybe_hot_reload(self):
        """Check if policy file changed and reload if so. Call periodically."""
        if not self._policy_file:
            return
        now = time.time()
        if now - self._last_check < 5.0:  # check every 5 seconds
            return
        self._last_check = now
        try:
            mtime = self._policy_file.stat().st_mtime
            if mtime > self._policy_mtime:
                logger.info("PolicyFirewall: Policy file changed, hot-reloading...")
                self.load_from_file(str(self._policy_file))
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        call: ToolCall,
        manifest: Optional[ToolManifest] = None,
        blast_radius: Optional[int] = None,
        session_risk: float = 0.0,
    ) -> PolicyEvaluationResult:
        """
        Evaluate a tool call against all loaded rules.
        Returns the first matching rule's decision, or default action.
        """
        self.maybe_hot_reload()
        alerts: List[Alert] = []

        for rule in self._rules:
            if rule.matches(call, manifest, blast_radius, session_risk):
                logger.debug(
                    "PolicyFirewall: Rule '%s' matched call '%s' -> %s",
                    rule.name, call.tool_name, rule.action.value
                )

                if rule.action in (SecurityAction.BLOCK, SecurityAction.REQUIRE_APPROVAL):
                    alerts.append(Alert(
                        severity=AlertSeverity.HIGH if rule.action == SecurityAction.BLOCK else AlertSeverity.MEDIUM,
                        title=f"Policy Rule Triggered: {rule.name}",
                        description=rule.description or f"Tool call blocked by policy rule '{rule.name}'.",
                        detector="PolicyFirewall",
                        tool_call_id=call.id,
                        session_id=call.session_id,
                        evidence={"rule": rule.name, "action": rule.action.value},
                    ))

                return PolicyEvaluationResult(
                    matched_rule=rule,
                    action=rule.action,
                    reason=rule.description or f"Matched rule: {rule.name}",
                    alerts=alerts,
                )

        return PolicyEvaluationResult(
            matched_rule=None,
            action=self._default_action,
            reason="No policy rule matched; using default action.",
        )

    def add_rule(self, rule: PolicyRule):
        """Programmatically add a rule."""
        rule.compile()
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority)

    @property
    def rule_count(self) -> int:
        return len(self._rules)
