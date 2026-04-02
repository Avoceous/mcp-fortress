# MCP-Fortress Changelog

All notable changes to MCP-Fortress will be documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-04-03

### Added — Initial Release 🛡️

#### Core Security Pipeline
- **TDIV** (Tool Description Integrity Verifier)
  - HMAC-SHA256 cryptographic signing of tool manifests
  - Invisible/zero-width character detection in descriptions (prompt injection via Unicode)
  - Prompt-override language detection
  - Injection keyword pattern matching (exfiltration, credential theft terms)
  - Schema hash change detection (rug pull detection)
  - Shadow tool detection via Levenshtein distance (typosquatting)
  - Description overlap similarity (tool shadowing)
  - Semantic drift analysis on description updates

- **BAD Engine** (Behavioral Anomaly Detector)
  - 10 built-in attack sequence signatures (exfiltration, enumeration, credential harvest, shell injection, etc.)
  - Sliding-window call velocity detection (calls/min + burst/sec)
  - Enumerate-then-destroy pattern detection
  - Per-session risk score accumulation (0.0–1.0)
  - Automatic session tagging (suspicious, high_risk)

- **BRE** (Blast Radius Estimator)
  - Pre-execution risk scoring 0–100 before forwarding to upstream
  - 8 risk factors: destructiveness class, data scope, reversibility, external network, sensitive path, sensitive args, external URLs, session history
  - Compound risk bonusing for multi-factor scenarios
  - Configurable auto-allow / require-approval / block thresholds
  - MITRE ATT&CK annotations on all findings

- **PII & Secret Scanner**
  - 22 built-in patterns: AWS keys, OpenAI, Anthropic, GitHub, Stripe, Slack, Twilio, SendGrid, npm, Azure
  - JWT token detection
  - Generic credential patterns (password=, secret=, api_key=)
  - Private key header detection
  - PII: email, phone, credit card, US SSN
  - Configurable redact / block / alert actions
  - Input AND output scanning

- **Cross-Session Correlator**
  - Sliding-window IP clustering (multiple sessions from same source)
  - High-risk session concentration detection
  - Global alert rate spike detection (broad scanning campaigns)
  - Slow-burn exfiltration detection (reads distributed across many sessions)
  - Per-user session anomaly detection

- **Policy-as-Code Firewall**
  - YAML and JSON rule files
  - Hot-reload (checks every 5s for file changes)
  - Match conditions: tool name, tool name regex, tool class, arg pattern regex, blast radius threshold, session risk threshold
  - Actions: ALLOW, BLOCK, ALERT, REQUIRE_APPROVAL, REDACT
  - Priority-ordered evaluation (lower number = higher priority)
  - Enterprise policy example with 15 rules out of the box

#### Transport
- HTTP proxy (FastAPI + httpx) — intercepts MCP JSON-RPC `tools/call` and `tools/list`
- Server-Sent Events (SSE) stream proxying
- Human approval queue with `/api/v1/approve/{id}` and `/api/v1/deny/{id}`
- JSONL audit log

#### Dashboard
- Real-time web dashboard at `/dashboard`
- Live alert feed with severity badges and MITRE ATT&CK IDs
- Session list with risk scores and session tags
- Pending approval queue with one-click approve/deny
- Registered tool inventory with trust status
- 20-minute activity timeline chart
- Toast notifications for critical/high alerts
- Zero dependencies — pure HTML/CSS/JS

#### Scanner
- Active vulnerability scanner (`mcp-fortress scan`)
- 9 check categories: AUTH, SSRF, PTRAV, TDIV, CORS, TLS, RATE, ENUM, VERBOSE
- HTML and JSON report output
- Tool discovery and TDIV verification built-in

#### CLI
- `mcp-fortress proxy` — start security proxy
- `mcp-fortress scan` — vulnerability scan
- `mcp-fortress verify` — verify tool manifest JSON
- `mcp-fortress report` — generate report from audit log

#### Infrastructure
- Docker image (non-root, read-only FS, CIS hardened)
- Docker Compose full stack (proxy + example MCP server + log viewer)
- GitHub Actions CI (Python 3.10/3.11/3.12, bandit security scan)
- 29 passing tests covering all 6 detectors + pipeline integration

### Security Coverage
All 10 OWASP MCP Top 10 risks addressed. See README for full matrix.

---

## Roadmap

### [0.2.0] — Planned

- [ ] stdio transport (protect local Claude Desktop / Cursor without running a server)
- [ ] ML-based prompt injection detector (small local model, CPU-only)
- [ ] `PromptShieldDetector` — LLM-in-the-loop validation for ambiguous calls
- [ ] Community policy library (`policies/community/`)
- [ ] Prometheus metrics endpoint (`/metrics`)
- [ ] Webhook alerts (Slack, PagerDuty, custom)
- [ ] Session persistence (Redis backend)
- [ ] Helm chart for Kubernetes

### [0.3.0] — Planned

- [ ] Multi-tenant mode (per-client policy isolation)
- [ ] RBAC: per-user tool permissions
- [ ] OpenTelemetry tracing
- [ ] Plugin API for community detectors
- [ ] MCP OAuth 2.1 (RFC 9728) native support
