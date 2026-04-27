# MCP-Fortress

**Production-grade security firewall & proxy for AI Agent MCP (Model Context Protocol)**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Security: OWASP MCP Top 10](https://img.shields.io/badge/Security-OWASP%20MCP%20Top%2010-red.svg)](https://owasp.org/www-project-mcp-top-10/)

> **The first open-source MCP security layer combining behavioral anomaly detection, cryptographic tool-integrity verification, blast-radius estimation, and cross-session threat correlation — built for real field usage in 2026.**

---

## Why MCP-Fortress?

The MCP ecosystem exploded in 2025-2026. So did the attacks:

- **82%** of MCP implementations have path traversal vulnerabilities *(security researchers, 2026)*
- **36.7%** of 7,000+ surveyed MCP servers are vulnerable to SSRF *(BlueRock Security, 2026)*
- **30 CVEs** filed against MCP infrastructure in just 60 days *(Jan-Feb 2026)*
- Tool poisoning, prompt injection, credential exfiltration — all confirmed in production

Existing gateways cover routing, auth, and rate limiting. **MCP-Fortress fills the security gaps they leave open:**

| Capability | Other Gateways | MCP-Fortress |
|---|---|---|
| OAuth / API Key auth | YES | YES |
| Rate limiting | YES | YES |
| Tool description integrity (crypto + semantic) | NO | YES |
| Behavioral anomaly detection (sequence analysis) | NO | YES |
| Blast-radius pre-execution scoring 0-100 | NO | YES |
| Cross-session threat correlation | NO | YES |
| Policy-as-Code firewall (zero cloud dependency) | NO | YES |
| Automated tool poisoning detection at load time | NO | YES |
| PII and secret scanner (inputs + outputs) | NO | YES |
| Zero external dependencies (stdlib core) | NO | YES |

---

## Core Security Modules

### 1. Tool Description Integrity Verifier (TDIV)
Detects tool poisoning — the #1 MCP attack vector in 2026.
- Cryptographic HMAC-SHA256 signing of tool manifests at registration
- Detects invisible/zero-width Unicode characters hidden in descriptions
- Semantic drift detection: flags when a tool description gains dangerous new capabilities
- Shadow tool detection: typosquatting via Levenshtein distance analysis
- Rug pull detection: alerts when a trusted tool silently updates its schema

### 2. Behavioral Anomaly Detector (BAD Engine)
Detects compromised agents through call-sequence analysis.
- 10 built-in attack patterns: exfiltration, enumeration, credential harvest, shell injection, etc.
- Velocity detection: calls/minute and burst/second thresholds
- Enumerate-then-destroy pattern detection
- Per-session risk scoring (0.0-1.0) with automatic tagging

### 3. Blast Radius Estimator (BRE)
Answers: "If this call is malicious, how bad is the damage?"
- Scores every tool call 0-100 before execution
- 8 risk factors: destructiveness, data scope, reversibility, external network, sensitive paths, args, URLs, session history
- Configurable: AUTO_ALLOW, REQUIRE_HUMAN_APPROVAL, BLOCK

### 4. Cross-Session Threat Correlator (CSTC)
Detects coordinated attacks across multiple agent sessions.
- IP clustering: multiple sessions from same source
- Slow-burn exfiltration: reads distributed across many short sessions
- Global alert rate spike detection (broad scanning campaigns)

### 5. Policy-as-Code Firewall
Declarative YAML security rules with hot-reload.

```yaml
rules:
  - name: "block_path_traversal"
    match: {arg_pattern: '\.\./'}
    action: BLOCK

  - name: "require_approval_shell"
    match: {tool_class: "shell_exec"}
    action: REQUIRE_APPROVAL

  - name: "allow_workspace_reads"
    match: {tool: "read_file", arg_pattern: "^/workspace/"}
    action: ALLOW
```

### 6. PII and Secret Scanner
Scans both inputs and outputs for 22+ secret patterns including AWS, OpenAI, Anthropic, GitHub, Stripe, Slack, Twilio, SendGrid keys, JWT tokens, private keys, credit cards, and SSNs. Configurable redact, block, or alert actions.

---

## Architecture

```
AI Agent (Claude / GPT / Cursor)
          | MCP JSON-RPC
          v
  +-------------------------------+
  |      MCP-Fortress Proxy       |
  |                               |
  |  [1] Policy Firewall          |  <- YAML rules, hot-reload
  |  [2] PII Scanner (inputs)     |  <- 22+ secret patterns
  |  [3] BAD Engine               |  <- sequence anomaly detection
  |  [4] Blast Radius Estimator   |  <- 0-100 pre-exec scoring
  |  [5] Cross-Session Correlator |  <- coordinated attack detection
  |  [6] PII Scanner (outputs)    |  <- redact before returning
  |                               |
  |  Dashboard  /dashboard        |  <- real-time web UI
  |  Approval   /api/v1/approve   |  <- human-in-the-loop
  +-------------------------------+
          | (if ALLOW)
          v
    Upstream MCP Server
```

---

## Quick Start

```bash
pip install mcp-fortress
```

Wrap any MCP server in 30 seconds:

```bash
mcp-fortress proxy \
  --upstream "http://localhost:3000" \
  --policy examples/policy_enterprise.yaml \
  --port 8100
```

Open the live dashboard at http://localhost:8100/dashboard

Protect Claude Desktop or Cursor with no server needed:

```json
{
  "mcpServers": {
    "filesystem-protected": {
      "command": "mcp-fortress-stdio",
      "args": [
        "--policy", "/path/to/policy_developer.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "."
      ]
    }
  }
}
```

Scan an MCP server for vulnerabilities:

```bash
mcp-fortress scan --target http://localhost:3000 --report report.html
```

---

## Installation

```bash
# Core (zero external dependencies)
pip install mcp-fortress

# With HTTP proxy and dashboard
pip install mcp-fortress[proxy,yaml]

# Full install
pip install mcp-fortress[all]
```

Docker:

```bash
docker run -p 8100:8100 \
  -v $(pwd)/examples/policy_enterprise.yaml:/app/config/policy.yaml \
  -e UPSTREAM_MCP_URL=http://your-mcp-server:3000 \
  ghcr.io/Avoceous/mcp-fortress:latest
```

---

## OWASP MCP Top 10 Coverage

| OWASP MCP Risk | MCP-Fortress Module |
|---|---|
| MCP-01: Prompt Injection | BAD Engine + Policy Firewall |
| MCP-02: Tool Poisoning | TDIV (full coverage) |
| MCP-03: Excessive Permissions | Blast Radius Estimator |
| MCP-04: Insecure Auth | API Key + JWT middleware |
| MCP-05: Supply Chain Risks | TDIV schema signing |
| MCP-06: Insufficient Logging | Full JSONL audit trail |
| MCP-07: Shadow MCP Servers | TDIV drift + shadow detection |
| MCP-08: Context Manipulation | Cross-Session Correlator |
| MCP-09: Scope Creep | Policy-as-Code enforcement |
| MCP-10: Command Injection | Arg sanitization + pattern rules |

---

## Project Structure

```
mcp-fortress/
├── mcpshield/
│   ├── core/
│   │   ├── models.py          <- Data types: ToolCall, SecurityDecision, Alert
│   │   └── pipeline.py        <- Unified 6-stage security pipeline
│   ├── detectors/
│   │   ├── tdiv.py            <- Tool Description Integrity Verifier
│   │   ├── bad_engine.py      <- Behavioral Anomaly Detector
│   │   ├── blast_radius.py    <- Blast Radius Estimator
│   │   ├── pii_scanner.py     <- PII and Secret Scanner
│   │   └── correlator.py      <- Cross-Session Correlator
│   ├── policy/
│   │   └── firewall.py        <- Policy-as-Code Firewall
│   ├── transport/
│   │   ├── proxy.py           <- HTTP/SSE Proxy (FastAPI)
│   │   ├── stdio_proxy.py     <- stdio Proxy (Claude Desktop / Cursor)
│   │   └── dashboard.html     <- Real-time security dashboard
│   └── cli/
│       ├── main.py            <- CLI: proxy, scan, verify, report
│       └── scanner.py         <- Active vulnerability scanner
├── tests/
│   └── test_all.py            <- 40 tests across all modules
├── examples/
│   ├── policy_enterprise.yaml <- 15-rule enterprise policy
│   └── policy_developer.yaml  <- Lightweight developer policy
├── docs/
│   └── developer_guide.md     <- Full API reference and Kubernetes guide
├── scripts/
│   └── setup_github.sh        <- One-command GitHub publish
├── Dockerfile
├── docker-compose.yml
└── pyproject.toml
```

---

## Configuration

```yaml
# mcp-fortress.yaml
mcpshield:
  proxy:
    host: "0.0.0.0"
    port: 8100
    upstream: "http://localhost:3000"

  integrity:
    enabled: true
    signing_key_env: "MCP_FORTRESS_SIGNING_KEY"

  behavioral:
    enabled: true
    max_calls_per_minute: 60

  blast_radius:
    enabled: true
    auto_allow_threshold: 20
    approval_threshold: 60
    block_threshold: 90

  pii_scanner:
    enabled: true
    action: "redact"

  audit:
    enabled: true
    log_file: "mcp_fortress_audit.jsonl"
```

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Security Disclosure

Found a vulnerability? Please use [private disclosure](SECURITY.md) and do not open a public issue.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Author

**w1boost1889M** — [https://github.com/w1boost1889M](https://github.com/w1boost1889M)

*Built to protect AI agents and the clients they serve.*
