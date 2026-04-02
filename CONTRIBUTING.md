# Contributing to MCP-Fortress

Thank you for helping make AI agents safer. 🛡️

## Quick Start

```bash
git clone https://github.com/Avoceous/mcp-fortress
cd mcp-fortress
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

## Project Structure

```
mcp-fortress/
  core/
    models.py      ← Core data types (ToolCall, SecurityDecision, etc.)
    pipeline.py    ← Unified security pipeline
  detectors/
    tdiv.py        ← Tool Description Integrity Verifier
    bad_engine.py  ← Behavioral Anomaly Detector
    blast_radius.py← Blast Radius Estimator
    pii_scanner.py ← PII & Secret Scanner
    correlator.py  ← Cross-Session Correlator
  policy/
    firewall.py    ← Policy-as-Code Firewall
  transport/
    proxy.py       ← HTTP/SSE Proxy Server
  cli/
    main.py        ← CLI entrypoint
    scanner.py     ← Vulnerability Scanner
tests/
  test_all.py      ← All unit + integration tests
examples/
  policy_enterprise.yaml
  policy_developer.yaml
```

## Priority Areas for Contribution

### 1. New Detectors (`mcp-fortress/detectors/`)
- `PromptInjectionDetector` — ML-based injection detection (use small local model)
- `ResourceAnomalyDetector` — Detect unusual MCP resource access patterns
- `ToolChainAnalyzer` — Deep multi-turn conversation analysis

### 2. Policy Rule Library (`examples/policies/`)
- `policy_healthcare.yaml` — HIPAA-aligned rules
- `policy_fintech.yaml` — PCI-DSS aligned rules
- `policy_devsec.yaml` — Secure coding assistant rules

### 3. MCP Server Integrations
- Integration tests against real MCP servers
- Specific rules for `@modelcontextprotocol/server-github`
- Specific rules for `@modelcontextprotocol/server-postgres`

### 4. Transport improvements
- stdio transport (for local Claude Desktop / Cursor protection)
- WebSocket full duplex support
- gRPC transport

## Writing a New Detector

Implement the interface:
```python
# mcp-fortress/detectors/my_detector.py
from mcp-fortress.core.models import Alert, ToolCall, SessionContext
from typing import List

class MyDetector:
    def analyze(self, call: ToolCall, session: SessionContext) -> List[Alert]:
        alerts = []
        # ... your logic
        return alerts
```

Then register it in `MCP-FortressPipeline.__init__()`.

## Tests

All PRs require tests. Run:
```bash
pytest tests/ -v --cov=mcp-fortress
```

Coverage must not drop below 80%.

## Code Style

```bash
ruff check mcp-fortress/   # linting
ruff format mcp-fortress/  # formatting
```

## Security Disclosures

Please see [SECURITY.md](SECURITY.md) for responsible disclosure policy.
Do NOT open public issues for vulnerabilities — email the maintainers directly.

## License

By contributing, you agree your contributions will be licensed under MIT.
