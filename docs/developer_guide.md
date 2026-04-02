# MCP-Fortress — Developer Guide

## Quickstart

```bash
# Clone and install
git clone https://github.com/Avoceous/mcp-fortress
cd mcp-fortress
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Start proxy wrapping a local MCP server
mcp-fortress proxy --upstream http://localhost:3000 --port 8100 --policy examples/policy_enterprise.yaml

# Open dashboard
open http://localhost:8100/dashboard

# Scan a running MCP server
mcp-fortress scan --target http://localhost:3000 --report report.html

# Verify tool manifest JSON
mcp-fortress verify tools.json

# View report from audit log
mcp-fortress report --log mcp-fortress_audit.jsonl
```

## Integrating MCP-Fortress as a Library

### Basic usage — evaluate a single tool call

```python
from mcp-fortress.core.pipeline import MCP-FortressPipeline
from mcp-fortress.core.models import ToolCall, ToolManifest, SessionContext

# Create pipeline (all detectors enabled by default)
pipeline = MCP-FortressPipeline()

# Register your trusted tools at startup
pipeline.register_tool(ToolManifest(
    name="read_file",
    description="Read the contents of a file from /workspace.",
    input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
    tool_class="fs_read",
    destructiveness=2,
    reversible=True,
    data_scope="local",
    external_network=False,
))

# On each agent tool call:
session = pipeline.get_or_create_session(
    session_id="user-abc-session-1",
    source_ip="10.0.0.5",
)

call = ToolCall(
    session_id="user-abc-session-1",
    tool_name="read_file",
    arguments={"path": "/workspace/notes.txt"},
)

decision = pipeline.evaluate_call(call, session)

if decision.is_allowed:
    result = your_mcp_server.call_tool(call)
    # Scan the output too:
    safe_result = pipeline.scan_output(result, call, decision)
    return safe_result
elif decision.requires_hold:
    await notify_human_for_approval(decision)
else:
    return {"error": f"Blocked: {decision.reason}"}
```

### Load from config file

```python
pipeline = MCP-FortressPipeline.from_config("mcp-fortress.yaml")
```

### Use individual detectors

```python
from mcp-fortress.detectors.tdiv import ToolDescriptionIntegrityVerifier
from mcp-fortress.detectors.pii_scanner import PIISecretScanner
from mcp-fortress.core.models import ToolManifest

# Just use TDIV for tool integrity checking
tdiv = ToolDescriptionIntegrityVerifier(signing_key="your-secret")

# Register at startup
for tool in your_tools:
    manifest = ToolManifest(name=tool["name"], description=tool["description"], ...)
    signature = tdiv.register(manifest)
    store_signature(tool["name"], signature)  # persist this

# Verify after server restart
is_clean, alerts = tdiv.verify(manifest)
if not is_clean:
    for alert in alerts:
        print(f"[{alert.severity.value}] {alert.title}")
```

```python
from mcp-fortress.detectors.pii_scanner import PIISecretScanner

scanner = PIISecretScanner(action="redact")

# Scan tool output
result = scanner.scan_text(raw_tool_output)
if result.has_findings:
    safe_output = result.redacted_text
    for finding in result.findings:
        print(f"Redacted {finding.pattern_name}")
```

### Programmatic policy rules

```python
from mcp-fortress.policy.firewall import PolicyFirewall, PolicyRule
from mcp-fortress.core.models import SecurityAction

fw = PolicyFirewall()
fw.add_rule(PolicyRule(
    name="block_path_traversal",
    action=SecurityAction.BLOCK,
    match_arg_pattern=r"\.\./|\.\.\\",
    description="Block path traversal",
    priority=1,
))
fw.add_rule(PolicyRule(
    name="require_approval_shell",
    action=SecurityAction.REQUIRE_APPROVAL,
    match_tool_class="shell_exec",
    priority=10,
))
```

## Architecture Deep Dive

### Security Pipeline Order

```
ToolCall received
    │
    ▼
[1] PolicyFirewall.evaluate()
    ├─ BLOCK → return error immediately (fastest path)
    └─ continue
    │
    ▼
[2] PIISecretScanner.scan_text(inputs)
    ├─ BLOCK (if action="block") → return error
    └─ continue (redact mode: flag but continue)
    │
    ▼
[3] BehavioralAnomalyDetector.analyze()
    └─ Raises alerts, updates session risk score
    │
    ▼
[4] BlastRadiusEstimator.estimate()
    ├─ score >= block_threshold → BLOCK
    ├─ score >= approval_threshold → REQUIRE_APPROVAL
    └─ score < auto_allow → ALLOW
    │
    ▼
[5] session.add_call(call)  ← record in session history
    │
    ▼
[6] CrossSessionCorrelator.correlate()
    └─ Raises alerts for cross-session threats
    │
    ▼
[7] Resolve final action (most restrictive wins)
    │
    ▼
[8] Forward to upstream MCP server (if ALLOW)
    │
    ▼
[9] PIISecretScanner.scan_text(output)
    └─ Redact secrets from upstream response
    │
    ▼
Return (possibly redacted) response to agent
```

### Adding a Custom Detector

```python
# mcp-fortress/detectors/my_detector.py
from __future__ import annotations
from typing import List
from mcp-fortress.core.models import Alert, AlertSeverity, SessionContext, ToolCall

class MyCustomDetector:
    """Detects [describe what it detects]."""

    def __init__(self, threshold: float = 0.7):
        self._threshold = threshold

    def analyze(self, call: ToolCall, session: SessionContext) -> List[Alert]:
        alerts = []

        # Your detection logic here
        if self._is_suspicious(call):
            alerts.append(Alert(
                severity=AlertSeverity.HIGH,
                title="My Custom Detection",
                description="Detected suspicious pattern X in tool call.",
                detector="MyCustomDetector",
                tool_call_id=call.id,
                session_id=session.session_id,
                evidence={"tool": call.tool_name},
                mitre_attack_id="T1234",
            ))

        return alerts

    def _is_suspicious(self, call: ToolCall) -> bool:
        # Your logic
        return False
```

Then wire it into the pipeline:

```python
from mcp-fortress.core.pipeline import MCP-FortressPipeline
from mcp-fortress.detectors.my_detector import MyCustomDetector

class ExtendedPipeline(MCP-FortressPipeline):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._my_detector = MyCustomDetector()

    def evaluate_call(self, call, session):
        # Run parent pipeline
        decision = super().evaluate_call(call, session)

        # Add your custom detector
        alerts = self._my_detector.analyze(call, session)
        decision.alerts.extend(alerts)

        return decision
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `MCPSHIELD_SIGNING_KEY` | `default-dev-key` | HMAC key for tool integrity signing |
| `UPSTREAM_MCP_URL` | `http://localhost:3000` | Docker: upstream MCP server URL |
| `MCPSHIELD_HOST` | `0.0.0.0` | Proxy bind host |
| `MCPSHIELD_PORT` | `8100` | Proxy port |
| `MCPSHIELD_POLICY` | `policy.yaml` | Policy file path |
| `MCPSHIELD_AUDIT_LOG` | `mcp-fortress_audit.jsonl` | Audit log file |

## Running in Production

### Kubernetes (minimal)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-fortress
spec:
  replicas: 2
  selector:
    matchLabels:
      app: mcp-fortress
  template:
    metadata:
      labels:
        app: mcp-fortress
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
      - name: mcp-fortress
        image: ghcr.io/Avoceous/mcp-fortress:latest
        ports:
        - containerPort: 8100
        env:
        - name: UPSTREAM_MCP_URL
          value: "http://mcp-server:3000"
        - name: MCPSHIELD_SIGNING_KEY
          valueFrom:
            secretKeyRef:
              name: mcp-fortress-secrets
              key: signing-key
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /api/v1/health
            port: 8100
          initialDelaySeconds: 10
          periodSeconds: 30
```

## Performance

MCP-Fortress adds ~2–5ms latency per tool call in typical deployments:

| Component | Typical latency |
|---|---|
| PolicyFirewall | < 0.1ms |
| PIIScanner (input) | 0.5–1ms |
| BehavioralAnomalyDetector | 0.2–0.5ms |
| BlastRadiusEstimator | 0.3–0.8ms |
| CrossSessionCorrelator | 0.1–0.3ms |
| PIIScanner (output) | 0.5–2ms |
| **Total** | **~2–5ms** |

At 99th percentile under load: < 15ms.
