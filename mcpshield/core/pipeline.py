# MCP-Fortress — by Avoceous (https://github.com/Avoceous) | MIT License
"""
MCP-Fortress Security Pipeline

Orchestrates all detectors in order:
  1. PolicyFirewall (fast, rule-based pre-check)
  2. ToolDescriptionIntegrityVerifier (tool manifest validation)
  3. BehavioralAnomalyDetector (sequence analysis)
  4. BlastRadiusEstimator (pre-execution risk scoring)
  5. PIISecretScanner (input scan)
  6. CrossSessionCorrelator (cross-session threats)
  7. PIISecretScanner (output scan, after upstream response)

Returns a SecurityDecision for every tool call.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from mcpshield.core.models import (
    Alert,
    AlertSeverity,
    SecurityAction,
    SecurityDecision,
    SessionContext,
    ToolCall,
    ToolManifest,
)
from mcpshield.detectors.bad_engine import BehavioralAnomalyDetector
from mcpshield.detectors.blast_radius import BlastRadiusEstimator
from mcpshield.detectors.correlator import CrossSessionCorrelator
from mcpshield.detectors.pii_scanner import PIISecretScanner
from mcpshield.detectors.tdiv import ToolDescriptionIntegrityVerifier
from mcpshield.policy.firewall import PolicyFirewall

logger = logging.getLogger(__name__)


class MCPFortressPipeline:
    """
    The main MCP-Fortress security evaluation pipeline.
    
    Usage:
        shield = MCPFortressPipeline.from_config("mcp-fortress.yaml")
        
        # Before forwarding a tool call to upstream:
        session = shield.get_or_create_session(session_id, source_ip=ip)
        decision = shield.evaluate_call(call, session)
        
        if decision.is_allowed:
            response = upstream.call(call)
            # Scan the response too:
            clean_response = shield.scan_output(response, call, decision)
            return clean_response
        else:
            return error_response(decision.reason)
    """

    def __init__(
        self,
        policy_firewall: Optional[PolicyFirewall] = None,
        tdiv: Optional[ToolDescriptionIntegrityVerifier] = None,
        bad_engine: Optional[BehavioralAnomalyDetector] = None,
        blast_radius: Optional[BlastRadiusEstimator] = None,
        pii_scanner: Optional[PIISecretScanner] = None,
        correlator: Optional[CrossSessionCorrelator] = None,
        tool_registry: Optional[Dict[str, ToolManifest]] = None,
        audit_log_path: Optional[str] = None,
    ):
        self._policy = policy_firewall or PolicyFirewall()
        self._tdiv = tdiv or ToolDescriptionIntegrityVerifier()
        self._bad = bad_engine or BehavioralAnomalyDetector()
        self._bre = blast_radius or BlastRadiusEstimator()
        self._pii = pii_scanner or PIISecretScanner()
        self._cstc = correlator or CrossSessionCorrelator()
        self._tools: Dict[str, ToolManifest] = tool_registry or {}
        self._sessions: Dict[str, SessionContext] = {}
        self._audit_path = audit_log_path
        self._audit_handle = None

        if audit_log_path:
            import pathlib
            pathlib.Path(audit_log_path).parent.mkdir(parents=True, exist_ok=True)
            self._audit_handle = open(audit_log_path, "a", encoding="utf-8")

    @classmethod
    def from_config(cls, config_path: str) -> "MCPFortressPipeline":
        """Create pipeline from a YAML/JSON config file."""
        import json
        from pathlib import Path

        p = Path(config_path)
        if not p.exists():
            logger.warning("Config file not found: %s — using defaults", config_path)
            return cls()

        content = p.read_text()
        if config_path.endswith(".yaml") or config_path.endswith(".yml"):
            try:
                import yaml
                cfg = yaml.safe_load(content).get("mcp-fortress", {})
            except ImportError:
                logger.error("PyYAML required for YAML config. Install: pip install pyyaml")
                return cls()
        else:
            cfg = json.loads(content).get("mcp-fortress", {})

        # Build components from config
        int_cfg = cfg.get("integrity", {})
        beh_cfg = cfg.get("behavioral", {})
        bre_cfg = cfg.get("blast_radius", {})
        pii_cfg = cfg.get("pii_scanner", {})
        cor_cfg = cfg.get("correlation", {})
        aud_cfg = cfg.get("audit", {})

        tdiv = ToolDescriptionIntegrityVerifier(
            semantic_drift_threshold=int_cfg.get("semantic_drift_threshold", 0.3),
        )
        bad = BehavioralAnomalyDetector(
            max_calls_per_minute=beh_cfg.get("max_calls_per_minute", 60),
            anomaly_sensitivity=beh_cfg.get("anomaly_sensitivity", 0.7),
        )
        bre = BlastRadiusEstimator(
            auto_allow_threshold=bre_cfg.get("auto_allow_threshold", 20),
            approval_threshold=bre_cfg.get("approval_threshold", 60),
            block_threshold=bre_cfg.get("block_threshold", 90),
        )
        pii = PIISecretScanner(
            action=pii_cfg.get("action", "redact"),
        )
        cstc = CrossSessionCorrelator(
            window_seconds=cor_cfg.get("window_seconds", 3600),
            alert_threshold=cor_cfg.get("alert_threshold", 3),
        )
        fw = PolicyFirewall()
        if "policy" in cfg and cfg["policy"].get("file"):
            fw.load_from_file(cfg["policy"]["file"])

        return cls(
            policy_firewall=fw,
            tdiv=tdiv,
            bad_engine=bad,
            blast_radius=bre,
            pii_scanner=pii,
            correlator=cstc,
            audit_log_path=aud_cfg.get("log_file"),
        )

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def get_or_create_session(
        self,
        session_id: str,
        source_ip: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> SessionContext:
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionContext(
                session_id=session_id,
                source_ip=source_ip,
                user_id=user_id,
            )
        return self._sessions[session_id]

    # ------------------------------------------------------------------
    # Tool registry
    # ------------------------------------------------------------------

    def register_tool(self, manifest: ToolManifest):
        """Register a tool as trusted baseline (call at startup)."""
        self._tdiv.register(manifest)
        self._tools[manifest.name] = manifest
        logger.info("Pipeline: Registered tool '%s'", manifest.name)

    def verify_tools(self, manifests: List[ToolManifest]) -> List[Alert]:
        """Verify a list of tool manifests (call when MCP server restarts)."""
        all_alerts = []

        # Check for shadow tools across the whole manifest set
        shadow_alerts = self._tdiv.detect_shadow_tools(manifests)
        all_alerts.extend(shadow_alerts)

        for manifest in manifests:
            is_clean, alerts = self._tdiv.verify(manifest)
            all_alerts.extend(alerts)
            if is_clean:
                self._tools[manifest.name] = manifest

        return all_alerts

    # ------------------------------------------------------------------
    # Main evaluation pipeline
    # ------------------------------------------------------------------

    def evaluate_call(
        self,
        call: ToolCall,
        session: SessionContext,
    ) -> SecurityDecision:
        """
        Run all detectors against a tool call.
        Returns SecurityDecision with final action.
        """
        start_time = time.time()
        all_alerts: List[Alert] = []
        manifest = self._tools.get(call.tool_name)

        # ---- Stage 1: Policy firewall (fast path) ----
        policy_result = self._policy.evaluate(call, manifest)
        all_alerts.extend(policy_result.alerts)

        if policy_result.action == SecurityAction.BLOCK:
            return self._make_decision(
                call, SecurityAction.BLOCK, policy_result.reason,
                policy_result.matched_rule.name if policy_result.matched_rule else "policy",
                all_alerts, start_time
            )

        # ---- Stage 2: PII scan on inputs ----
        input_text = " ".join(call.arg_values_as_strings())
        pii_result = self._pii.scan_text(input_text, context="input", call_id=call.id)
        all_alerts.extend(pii_result.alerts)

        if pii_result.has_findings and self._pii._action == "block":
            return self._make_decision(
                call, SecurityAction.BLOCK, "Input contains secrets or PII",
                "PIIScanner", all_alerts, start_time
            )

        # ---- Stage 3: Behavioral analysis ----
        bad_alerts = self._bad.analyze(call, session)
        all_alerts.extend(bad_alerts)

        # ---- Stage 4: Blast radius estimation ----
        bre_result = self._bre.estimate(call, manifest, session)
        all_alerts.extend(bre_result.alerts)

        # ---- Stage 5: Cross-session correlation ----
        session.add_call(call)
        corr_alerts = self._cstc.correlate(session, self._sessions)
        all_alerts.extend(corr_alerts)

        # ---- Final decision: most restrictive wins ----
        final_action = self._resolve_action(policy_result.action, bre_result.action, bad_alerts, corr_alerts)
        final_reason = bre_result.summary if bre_result.action != SecurityAction.ALLOW else "All checks passed."

        decision = self._make_decision(
            call, final_action, final_reason, None, all_alerts, start_time,
            blast_radius_score=bre_result.score
        )

        # ---- Audit log ----
        self._audit(call, session, decision)

        return decision

    def scan_output(
        self,
        output: Any,
        call: ToolCall,
        decision: SecurityDecision,
    ) -> Any:
        """
        Scan upstream MCP server output for secrets/PII.
        Returns (possibly redacted) output.
        """
        if isinstance(output, str):
            result = self._pii.scan_text(output, context="output", call_id=call.id)
        elif isinstance(output, dict):
            result = self._pii.scan_json(output, context="output", call_id=call.id)
        else:
            return output

        if result.has_findings:
            decision.alerts.extend(result.alerts)
            if self._pii._action == "redact" and result.redacted_text:
                logger.warning(
                    "Pipeline: Redacted %d secret(s)/PII from output of '%s'",
                    len(result.findings), call.tool_name
                )
                return result.redacted_text

        return output

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_action(
        self,
        policy_action: SecurityAction,
        bre_action: SecurityAction,
        bad_alerts: List[Alert],
        corr_alerts: List[Alert],
    ) -> SecurityAction:
        """Apply most-restrictive-wins logic across all detector outputs."""
        priority = [
            SecurityAction.BLOCK,
            SecurityAction.REQUIRE_APPROVAL,
            SecurityAction.ALERT,
            SecurityAction.ALLOW,
        ]

        candidates = [policy_action, bre_action]

        # Critical BAD alerts → require approval at minimum
        has_critical_bad = any(a.severity == AlertSeverity.CRITICAL for a in bad_alerts)
        has_high_bad = any(a.severity == AlertSeverity.HIGH for a in bad_alerts)
        has_critical_corr = any(a.severity == AlertSeverity.CRITICAL for a in corr_alerts)

        if has_critical_bad or has_critical_corr:
            candidates.append(SecurityAction.REQUIRE_APPROVAL)
        elif has_high_bad:
            candidates.append(SecurityAction.ALERT)

        for action in priority:
            if action in candidates:
                return action
        return SecurityAction.ALLOW

    def _make_decision(
        self,
        call: ToolCall,
        action: SecurityAction,
        reason: str,
        rule_name: Optional[str],
        alerts: List[Alert],
        start_time: float,
        blast_radius_score: Optional[int] = None,
    ) -> SecurityDecision:
        return SecurityDecision(
            call_id=call.id,
            action=action,
            reason=reason,
            rule_name=rule_name,
            blast_radius_score=blast_radius_score,
            alerts=alerts,
            duration_ms=(time.time() - start_time) * 1000,
        )

    def _audit(self, call: ToolCall, session: SessionContext, decision: SecurityDecision):
        if not self._audit_handle:
            return
        import json
        entry = {
            "ts": time.time(),
            "session_id": session.session_id[:8],
            "tool": call.tool_name,
            "action": decision.action.value,
            "blast_radius": decision.blast_radius_score,
            "alerts": len(decision.alerts),
            "duration_ms": round(decision.duration_ms, 2),
        }
        self._audit_handle.write(json.dumps(entry) + "\n")
        self._audit_handle.flush()

    def __del__(self):
        if self._audit_handle:
            self._audit_handle.close()
