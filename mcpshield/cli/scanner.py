# MCP-Fortress — by Avoceous (https://github.com/Avoceous) | MIT License
"""
MCP-Fortress Vulnerability Scanner

Actively probes a running MCP server for common vulnerabilities:

  [AUTH]   Missing or bypassable authentication
  [SSRF]   Server-Side Request Forgery via URL arguments
  [PTRAV]  Path traversal in file tool arguments
  [INJECT] Prompt injection susceptibility in tool descriptions
  [TDIV]   Tool description integrity issues
  [ENUM]   Sensitive tool/resource enumeration exposure
  [TLS]    Transport security issues
  [CORS]   Overly permissive CORS headers
  [RATE]   Missing rate limiting
  [LOG]    Audit log / observability gaps

Usage:
    scanner = MCPScanner(target="http://localhost:3000")
    report = scanner.run()
    report.print_summary()
    report.save("report.html")

Requires: httpx (pip install mcp-fortress[proxy])
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import httpx
    _HTTP_AVAILABLE = True
except ImportError:
    _HTTP_AVAILABLE = False

from mcpshield.core.models import AlertSeverity
from mcpshield.detectors.tdiv import ToolDescriptionIntegrityVerifier


@dataclass
class ScanFinding:
    check_id: str
    severity: AlertSeverity
    title: str
    description: str
    remediation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    cve: Optional[str] = None
    owasp_mcp: Optional[str] = None


@dataclass
class ScanReport:
    target: str
    scan_start: float
    scan_end: float
    findings: List[ScanFinding] = field(default_factory=list)
    tools_discovered: List[Dict] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def duration_seconds(self) -> float:
        return self.scan_end - self.scan_start

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == AlertSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == AlertSeverity.HIGH)

    def print_summary(self):
        bar = "═" * 52
        print(f"\n╔{bar}╗")
        print(f"║{'MCP-Fortress Vulnerability Scanner Report':^52}║")
        print(f"╚{bar}╝")
        print(f"\n  Target  : {self.target}")
        print(f"  Duration: {self.duration_seconds:.1f}s")
        print(f"  Tools   : {len(self.tools_discovered)} discovered\n")

        severity_order = [AlertSeverity.CRITICAL, AlertSeverity.HIGH, AlertSeverity.MEDIUM, AlertSeverity.LOW]
        counts = {s: sum(1 for f in self.findings if f.severity == s) for s in severity_order}

        print(f"  ┌─────────────────────────────────┐")
        print(f"  │  CRITICAL  {counts[AlertSeverity.CRITICAL]:>3}  │  HIGH   {counts[AlertSeverity.HIGH]:>3}  │")
        print(f"  │  MEDIUM    {counts[AlertSeverity.MEDIUM]:>3}  │  LOW    {counts[AlertSeverity.LOW]:>3}  │")
        print(f"  └─────────────────────────────────┘\n")

        if not self.findings:
            print("  ✅ No vulnerabilities found!\n")
            return

        for sev in severity_order:
            sev_findings = [f for f in self.findings if f.severity == sev]
            if not sev_findings:
                continue
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(sev.value, "⚪")
            print(f"  {icon} {sev.value.upper()} ({len(sev_findings)})")
            for f in sev_findings:
                print(f"     [{f.check_id}] {f.title}")
                if f.cve:
                    print(f"              CVE: {f.cve}")
                if f.owasp_mcp:
                    print(f"              OWASP-MCP: {f.owasp_mcp}")
                print(f"              ↳ {f.remediation}")
            print()

    def save(self, path: str):
        if path.endswith(".html"):
            self._save_html(path)
        else:
            self._save_json(path)

    def _save_json(self, path: str):
        import dataclasses
        data = {
            "target": self.target,
            "scan_start": self.scan_start,
            "duration_seconds": self.duration_seconds,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "remediation": f.remediation,
                    "evidence": f.evidence,
                    "cve": f.cve,
                    "owasp_mcp": f.owasp_mcp,
                }
                for f in self.findings
            ],
            "tools_discovered": self.tools_discovered,
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"📄 JSON report saved to {path}")

    def _save_html(self, path: str):
        sev_colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#ca8a04",
            "low": "#2563eb",
            "info": "#6b7280",
        }
        rows = ""
        for f in self.findings:
            color = sev_colors.get(f.severity.value, "#6b7280")
            rows += f"""
            <tr>
              <td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px">{f.severity.value.upper()}</span></td>
              <td><code>{f.check_id}</code></td>
              <td><strong>{f.title}</strong><br><small>{f.description[:120]}...</small></td>
              <td><small>{f.remediation}</small></td>
              <td>{f.cve or ''}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>MCP-Fortress Scan Report — {self.target}</title>
<style>
  body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; margin:40px; background:#f9fafb; color:#111; }}
  h1 {{ color:#1e293b; }} h2 {{ color:#475569; margin-top:32px; }}
  table {{ width:100%; border-collapse:collapse; background:#fff; border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.1); }}
  th {{ background:#1e293b; color:#fff; padding:10px 14px; text-align:left; font-size:13px; }}
  td {{ padding:10px 14px; border-bottom:1px solid #e2e8f0; vertical-align:top; font-size:13px; }}
  tr:hover td {{ background:#f1f5f9; }}
  .stat {{ display:inline-block; padding:16px 24px; background:#fff; border-radius:8px; margin:8px; box-shadow:0 1px 3px rgba(0,0,0,.1); text-align:center; }}
  .stat-number {{ font-size:32px; font-weight:700; }}
  .critical {{ color:#dc2626; }} .high {{ color:#ea580c; }}
  .medium {{ color:#ca8a04; }} .low {{ color:#2563eb; }}
</style>
</head>
<body>
<h1>🛡️ MCP-Fortress Vulnerability Report</h1>
<p>Target: <code>{self.target}</code> &nbsp;|&nbsp; Scan time: {self.duration_seconds:.1f}s &nbsp;|&nbsp; Tools found: {len(self.tools_discovered)}</p>

<div>
  <div class="stat"><div class="stat-number critical">{self.critical_count}</div><div>CRITICAL</div></div>
  <div class="stat"><div class="stat-number high">{self.high_count}</div><div>HIGH</div></div>
  <div class="stat"><div class="stat-number medium">{sum(1 for f in self.findings if f.severity==AlertSeverity.MEDIUM)}</div><div>MEDIUM</div></div>
  <div class="stat"><div class="stat-number low">{sum(1 for f in self.findings if f.severity==AlertSeverity.LOW)}</div><div>LOW</div></div>
</div>

<h2>Findings</h2>
<table>
  <tr><th>Severity</th><th>Check</th><th>Finding</th><th>Remediation</th><th>CVE</th></tr>
  {rows if rows else '<tr><td colspan="5" style="text-align:center;padding:24px">✅ No vulnerabilities found</td></tr>'}
</table>

<h2>Tools Discovered ({len(self.tools_discovered)})</h2>
<table>
  <tr><th>Name</th><th>Description</th></tr>
  {''.join(f'<tr><td><code>{t.get("name","?")}</code></td><td>{t.get("description","")[:100]}</td></tr>' for t in self.tools_discovered)}
</table>
</body></html>"""

        with open(path, "w") as f:
            f.write(html)
        print(f"📄 HTML report saved to {path}")


class MCPScanner:
    """
    Active vulnerability scanner for MCP servers.

    Sends crafted JSON-RPC probes to detect misconfigurations and vulnerabilities.
    Does NOT exploit — only probes and reports.
    """

    def __init__(self, target: str, timeout: int = 30, auth_token: Optional[str] = None):
        if not _HTTP_AVAILABLE:
            raise ImportError("Scanner requires: pip install mcp-fortress[proxy]")
        self._target = target.rstrip("/")
        self._timeout = timeout
        self._auth = auth_token

    def run(self) -> ScanReport:
        """Run all checks synchronously."""
        import asyncio
        return asyncio.run(self.run_async())

    async def run_async(self) -> ScanReport:
        """Run all checks asynchronously."""
        start = time.time()
        findings: List[ScanFinding] = []
        tools: List[Dict] = []

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            # First: discover tools (needed by many checks)
            tools = await self._discover_tools(client)

            # Run all check modules
            checks = [
                self._check_auth(client),
                self._check_ssrf(client, tools),
                self._check_path_traversal(client, tools),
                self._check_tool_description_integrity(tools),
                self._check_cors(client),
                self._check_tls(),
                self._check_rate_limiting(client),
                self._check_sensitive_tool_exposure(tools),
                self._check_error_verbosity(client),
            ]

            for coro in checks:
                try:
                    result = await coro
                    if result:
                        findings.extend(result if isinstance(result, list) else [result])
                except Exception as e:
                    logger.debug("Check failed: %s", e)

        return ScanReport(
            target=self._target,
            scan_start=start,
            scan_end=time.time(),
            findings=findings,
            tools_discovered=tools,
        )

    # ------------------------------------------------------------------
    # Tool discovery
    # ------------------------------------------------------------------

    async def _discover_tools(self, client: "httpx.AsyncClient") -> List[Dict]:
        """Send tools/list to enumerate all available tools."""
        try:
            resp = await client.post(
                f"{self._target}/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                headers=self._base_headers(),
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("result", {}).get("tools", [])
        except Exception as e:
            logger.debug("Tool discovery failed: %s", e)
        return []

    # ------------------------------------------------------------------
    # AUTH check
    # ------------------------------------------------------------------

    async def _check_auth(self, client: "httpx.AsyncClient") -> List[ScanFinding]:
        findings = []
        try:
            # Try without any auth headers
            resp = await client.post(
                f"{self._target}/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                headers={"Content-Type": "application/json"},  # No auth
            )
            if resp.status_code == 200:
                data = resp.json()
                if "result" in data:
                    findings.append(ScanFinding(
                        check_id="AUTH-001",
                        severity=AlertSeverity.CRITICAL,
                        title="MCP Server Accessible Without Authentication",
                        description=(
                            "The MCP server responds to tools/list without any authentication token. "
                            "Any client can enumerate and call tools without credentials."
                        ),
                        remediation=(
                            "Implement API key or OAuth 2.1 authentication. "
                            "Reject requests without valid Authorization headers."
                        ),
                        evidence={"status_code": resp.status_code, "method": "tools/list"},
                        owasp_mcp="MCP-04: Insecure Authentication",
                    ))
        except Exception:
            pass
        return findings

    # ------------------------------------------------------------------
    # SSRF check
    # ------------------------------------------------------------------

    async def _check_ssrf(self, client: "httpx.AsyncClient", tools: List[Dict]) -> List[ScanFinding]:
        findings = []
        url_tools = [t for t in tools if self._tool_accepts_url(t)]

        for tool in url_tools[:3]:  # Limit to first 3 to avoid noise
            try:
                resp = await client.post(
                    f"{self._target}/mcp",
                    json={
                        "jsonrpc": "2.0", "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": tool["name"],
                            "arguments": {"url": "http://169.254.169.254/latest/meta-data/"},
                        },
                    },
                    headers=self._base_headers(),
                )
                data = resp.json()
                result_str = json.dumps(data)
                if any(kw in result_str.lower() for kw in ["ami-id", "instance-id", "iam", "security-credentials"]):
                    findings.append(ScanFinding(
                        check_id="SSRF-001",
                        severity=AlertSeverity.CRITICAL,
                        title=f"SSRF: AWS Metadata Accessible via '{tool['name']}'",
                        description=(
                            f"Tool '{tool['name']}' can be used to reach the AWS EC2 metadata service "
                            "(169.254.169.254). An attacker can steal IAM credentials."
                        ),
                        remediation="Validate URLs against an allowlist. Block requests to 169.254.0.0/16, 10.x, 172.16-31.x, 192.168.x.",
                        evidence={"tool": tool["name"], "probe_url": "169.254.169.254"},
                        cve="CVE-2019-11043-class",
                        owasp_mcp="MCP-03: Excessive Permissions",
                    ))
                elif "error" not in data:
                    findings.append(ScanFinding(
                        check_id="SSRF-002",
                        severity=AlertSeverity.HIGH,
                        title=f"Potential SSRF via Tool '{tool['name']}'",
                        description=(
                            f"Tool '{tool['name']}' accepted an SSRF probe URL without obvious validation. "
                            "Internal network resources may be reachable."
                        ),
                        remediation="Implement strict URL allowlist validation before making network requests.",
                        evidence={"tool": tool["name"]},
                        owasp_mcp="MCP-10: Command Injection",
                    ))
            except Exception:
                pass
        return findings

    # ------------------------------------------------------------------
    # Path traversal check
    # ------------------------------------------------------------------

    async def _check_path_traversal(self, client: "httpx.AsyncClient", tools: List[Dict]) -> List[ScanFinding]:
        findings = []
        file_tools = [t for t in tools if self._tool_is_filesystem(t)]
        traversal_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2fetc/passwd",
        ]

        for tool in file_tools[:2]:
            for payload in traversal_payloads[:1]:
                try:
                    resp = await client.post(
                        f"{self._target}/mcp",
                        json={
                            "jsonrpc": "2.0", "id": 1,
                            "method": "tools/call",
                            "params": {"name": tool["name"], "arguments": {"path": payload}},
                        },
                        headers=self._base_headers(),
                    )
                    result_str = json.dumps(resp.json())
                    if any(kw in result_str for kw in ["root:x:", "[extensions]", "nobody"]):
                        findings.append(ScanFinding(
                            check_id="PTRAV-001",
                            severity=AlertSeverity.CRITICAL,
                            title=f"Path Traversal in '{tool['name']}'",
                            description=f"Tool '{tool['name']}' is vulnerable to path traversal. System files readable.",
                            remediation="Resolve and validate all paths to a safe root directory using os.path.realpath() + prefix check.",
                            evidence={"tool": tool["name"], "payload": payload},
                            owasp_mcp="MCP-10: Command Injection",
                        ))
                    elif "error" not in resp.json():
                        findings.append(ScanFinding(
                            check_id="PTRAV-002",
                            severity=AlertSeverity.MEDIUM,
                            title=f"Possible Path Traversal in '{tool['name']}'",
                            description=f"Tool '{tool['name']}' did not reject path traversal payload.",
                            remediation="Validate all file paths against an allowed base directory.",
                            evidence={"tool": tool["name"], "payload": payload},
                        ))
                except Exception:
                    pass
        return findings

    # ------------------------------------------------------------------
    # Tool description integrity
    # ------------------------------------------------------------------

    async def _check_tool_description_integrity(self, tools: List[Dict]) -> List[ScanFinding]:
        findings = []
        from mcpshield.core.models import ToolManifest
        tdiv = ToolDescriptionIntegrityVerifier()
        manifests = []

        for t in tools:
            m = ToolManifest(
                name=t.get("name", "unknown"),
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {}),
            )
            manifests.append(m)

        shadow_alerts = tdiv.detect_shadow_tools(manifests)
        for alert in shadow_alerts:
            findings.append(ScanFinding(
                check_id="TDIV-001",
                severity=alert.severity,
                title=alert.title,
                description=alert.description,
                remediation="Remove duplicate or similarly-named tools. Implement tool signing.",
                owasp_mcp="MCP-02: Tool Poisoning",
            ))

        for m in manifests:
            _, alerts = tdiv.verify(m)
            for alert in alerts:
                if alert.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL):
                    findings.append(ScanFinding(
                        check_id="TDIV-002",
                        severity=alert.severity,
                        title=alert.title,
                        description=alert.description,
                        remediation="Review tool descriptions for injected instructions. Implement HMAC signing.",
                        owasp_mcp="MCP-02: Tool Poisoning",
                    ))
        return findings

    # ------------------------------------------------------------------
    # CORS check
    # ------------------------------------------------------------------

    async def _check_cors(self, client: "httpx.AsyncClient") -> List[ScanFinding]:
        findings = []
        try:
            resp = await client.options(
                f"{self._target}/mcp",
                headers={"Origin": "https://evil-attacker.com", "Content-Type": "application/json"},
            )
            acao = resp.headers.get("access-control-allow-origin", "")
            if acao == "*" or acao == "https://evil-attacker.com":
                findings.append(ScanFinding(
                    check_id="CORS-001",
                    severity=AlertSeverity.HIGH,
                    title="Overly Permissive CORS Policy",
                    description=(
                        f"The server returns Access-Control-Allow-Origin: {acao}. "
                        "This allows any website to make cross-origin requests to this MCP server."
                    ),
                    remediation="Restrict CORS to known AI client origins. Never use wildcard (*) in production.",
                    evidence={"acao_header": acao},
                    owasp_mcp="MCP-04: Insecure Authentication",
                ))
        except Exception:
            pass
        return findings

    # ------------------------------------------------------------------
    # TLS check
    # ------------------------------------------------------------------

    async def _check_tls(self) -> List[ScanFinding]:
        findings = []
        if self._target.startswith("http://"):
            findings.append(ScanFinding(
                check_id="TLS-001",
                severity=AlertSeverity.HIGH,
                title="MCP Server Not Using TLS",
                description=(
                    "The MCP server is accessible over plain HTTP. "
                    "Tool arguments and responses (which may contain credentials) are transmitted unencrypted."
                ),
                remediation="Configure TLS/HTTPS with a valid certificate. Use a reverse proxy (nginx/caddy) if needed.",
                owasp_mcp="MCP-04: Insecure Authentication",
            ))
        return findings

    # ------------------------------------------------------------------
    # Rate limiting check
    # ------------------------------------------------------------------

    async def _check_rate_limiting(self, client: "httpx.AsyncClient") -> List[ScanFinding]:
        findings = []
        try:
            # Send 20 requests in quick succession
            tasks = [
                client.post(
                    f"{self._target}/mcp",
                    json={"jsonrpc": "2.0", "id": i, "method": "tools/list", "params": {}},
                    headers=self._base_headers(),
                )
                for i in range(20)
            ]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            rate_limited = sum(
                1 for r in responses
                if isinstance(r, httpx.Response) and r.status_code == 429
            )
            if rate_limited == 0:
                findings.append(ScanFinding(
                    check_id="RATE-001",
                    severity=AlertSeverity.MEDIUM,
                    title="No Rate Limiting Detected",
                    description=(
                        "Sent 20 rapid requests with no rate limiting response (HTTP 429). "
                        "Without rate limits, attackers can enumerate tools or brute-force at high speed."
                    ),
                    remediation="Implement per-IP and per-session rate limiting. Return HTTP 429 with Retry-After header.",
                    owasp_mcp="MCP-09: Scope Creep",
                ))
        except Exception:
            pass
        return findings

    # ------------------------------------------------------------------
    # Sensitive tool exposure
    # ------------------------------------------------------------------

    async def _check_sensitive_tool_exposure(self, tools: List[Dict]) -> List[ScanFinding]:
        findings = []
        dangerous_names = [
            ("shell", "Shell execution tool exposed"),
            ("exec", "Code execution tool exposed"),
            ("eval", "Eval tool exposed"),
            ("system", "System tool exposed"),
            ("admin", "Admin tool exposed"),
            ("debug", "Debug tool exposed — remove before production"),
            ("delete_all", "Mass-delete tool exposed"),
        ]
        for tool in tools:
            name_lower = tool.get("name", "").lower()
            for keyword, msg in dangerous_names:
                if keyword in name_lower:
                    findings.append(ScanFinding(
                        check_id="ENUM-001",
                        severity=AlertSeverity.HIGH,
                        title=f"Dangerous Tool Exposed: {tool['name']}",
                        description=f"{msg}: '{tool['name']}'. This tool should not be publicly accessible.",
                        remediation="Remove debug/admin tools from production. Apply RBAC to restrict sensitive tools.",
                        evidence={"tool": tool["name"]},
                        owasp_mcp="MCP-03: Excessive Permissions",
                    ))
        return findings

    # ------------------------------------------------------------------
    # Error verbosity
    # ------------------------------------------------------------------

    async def _check_error_verbosity(self, client: "httpx.AsyncClient") -> List[ScanFinding]:
        findings = []
        try:
            resp = await client.post(
                f"{self._target}/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "nonexistent_tool_xyz", "arguments": {}}},
                headers=self._base_headers(),
            )
            result = json.dumps(resp.json())
            verbose_indicators = ["traceback", "stack trace", "at line", "File \"", "Exception in", "Traceback (most recent"]
            if any(v.lower() in result.lower() for v in verbose_indicators):
                findings.append(ScanFinding(
                    check_id="VERBOSE-001",
                    severity=AlertSeverity.MEDIUM,
                    title="Verbose Error Messages Exposed",
                    description="Error responses include stack traces or internal paths, aiding attacker reconnaissance.",
                    remediation="Return generic error messages in production. Log detailed errors server-side only.",
                    owasp_mcp="MCP-06: Insufficient Logging",
                ))
        except Exception:
            pass
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _base_headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._auth:
            h["Authorization"] = f"Bearer {self._auth}"
        return h

    def _tool_accepts_url(self, tool: Dict) -> bool:
        schema = tool.get("inputSchema", {})
        props = schema.get("properties", {})
        return any(
            "url" in k.lower() or "uri" in k.lower() or "endpoint" in k.lower()
            for k in props.keys()
        )

    def _tool_is_filesystem(self, tool: Dict) -> bool:
        name = tool.get("name", "").lower()
        schema = tool.get("inputSchema", {})
        props = schema.get("properties", {})
        has_path_arg = any("path" in k.lower() or "file" in k.lower() for k in props.keys())
        has_file_name = any(k in name for k in ["read", "write", "file", "open", "cat"])
        return has_path_arg or has_file_name


import asyncio  # needed at module level for gather
