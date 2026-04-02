# MCP-Fortress — by Avoceous (https://github.com/Avoceous) | MIT License
"""
MCP-Fortress CLI

Commands:
  mcp-fortress proxy    — Start the security proxy in front of an MCP server
  mcp-fortress scan     — Scan an MCP server for vulnerabilities
  mcp-fortress verify   — Verify tool manifest integrity
  mcp-fortress report   — Generate security report from audit log
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

logger = logging.getLogger("mcp-fortress")


def cmd_proxy(args):
    """Start the MCP-Fortress proxy server."""
    try:
        from mcpshield.transport.proxy import ProxyServer
        server = ProxyServer(
            upstream=args.upstream,
            host=args.host,
            port=args.port,
            config=args.config,
            policy=args.policy,
        )
        print(f"🛡️  MCP-Fortress proxy listening on {args.host}:{args.port}")
        print(f"   Upstream: {args.upstream}")
        if args.policy:
            print(f"   Policy: {args.policy}")
        server.run()
    except ImportError as e:
        print(f"❌ Proxy requires additional dependencies: {e}")
        print("   Install: pip install mcp-fortress[proxy]")
        sys.exit(1)


def cmd_scan(args):
    """Scan an MCP server for vulnerabilities."""
    from mcpshield.cli.scanner import MCPScanner
    scanner = MCPScanner(target=args.target, timeout=args.timeout)
    print(f"🔍 Scanning MCP server at {args.target}...")
    report = scanner.run()
    
    if args.report:
        report.save(args.report)
        print(f"📄 Report saved to {args.report}")
    else:
        report.print_summary()


def cmd_verify(args):
    """Verify a tool manifest JSON file."""
    import pathlib
    from mcpshield.detectors.tdiv import ToolDescriptionIntegrityVerifier
    from mcpshield.core.models import ToolManifest

    p = pathlib.Path(args.manifest)
    if not p.exists():
        print(f"❌ File not found: {args.manifest}")
        sys.exit(1)

    data = json.loads(p.read_text())
    tools = data if isinstance(data, list) else [data]
    
    tdiv = ToolDescriptionIntegrityVerifier()
    manifests = []
    
    for t in tools:
        m = ToolManifest(
            name=t.get("name", "unknown"),
            description=t.get("description", ""),
            input_schema=t.get("inputSchema", {}),
        )
        manifests.append(m)
    
    print(f"🔐 Verifying {len(manifests)} tool(s)...\n")
    
    shadow_alerts = tdiv.detect_shadow_tools(manifests)
    total_issues = len(shadow_alerts)
    
    for m in manifests:
        tdiv.register(m)
        is_clean, alerts = tdiv.verify(m)
        total_issues += len(alerts)
        status = "✅" if is_clean else "⚠️ "
        print(f"  {status} {m.name}")
        for a in alerts:
            print(f"     [{a.severity.value.upper()}] {a.title}")
    
    if shadow_alerts:
        print("\n⚠️  Shadow tool detections:")
        for a in shadow_alerts:
            print(f"  [{a.severity.value.upper()}] {a.title}: {a.description}")
    
    print(f"\nTotal issues: {total_issues}")
    sys.exit(0 if total_issues == 0 else 1)


def cmd_report(args):
    """Generate a security report from an audit log."""
    import pathlib
    p = pathlib.Path(args.log)
    if not p.exists():
        print(f"❌ Audit log not found: {args.log}")
        sys.exit(1)

    lines = p.read_text().strip().split("\n")
    entries = [json.loads(l) for l in lines if l.strip()]

    total = len(entries)
    blocked = sum(1 for e in entries if e.get("action") == "block")
    alerts = sum(1 for e in entries if e.get("alerts", 0) > 0)
    high_br = sum(1 for e in entries if (e.get("blast_radius") or 0) >= 60)

    print(f"""
╔══════════════════════════════════════════╗
║        MCP-Fortress Security Report         ║
╚══════════════════════════════════════════╝

  Total tool calls:    {total:>6}
  Blocked calls:       {blocked:>6}  ({blocked/max(total,1)*100:.1f}%)
  Calls with alerts:   {alerts:>6}  ({alerts/max(total,1)*100:.1f}%)
  High blast radius:   {high_br:>6}  ({high_br/max(total,1)*100:.1f}%)

  Top tools called:
""")

    from collections import Counter
    tool_counts = Counter(e.get("tool") for e in entries)
    for tool, count in tool_counts.most_common(10):
        print(f"    {count:>6}x  {tool}")


def main():
    parser = argparse.ArgumentParser(
        prog="mcp-fortress",
        description="🛡️  MCP-Fortress — Production-grade security for AI Agent MCP",
    )
    parser.add_argument("--version", action="version", version="mcp-fortress 0.1.0")
    parser.add_argument("-v", "--verbose", action="store_true")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- proxy ---
    p_proxy = subparsers.add_parser("proxy", help="Start security proxy")
    p_proxy.add_argument("--upstream", required=True, help="Upstream MCP server URL or command")
    p_proxy.add_argument("--host", default="127.0.0.1")
    p_proxy.add_argument("--port", type=int, default=8100)
    p_proxy.add_argument("--config", default="mcp-fortress.yaml")
    p_proxy.add_argument("--policy", default=None)

    # --- scan ---
    p_scan = subparsers.add_parser("scan", help="Scan MCP server for vulnerabilities")
    p_scan.add_argument("--target", required=True, help="MCP server URL")
    p_scan.add_argument("--timeout", type=int, default=30)
    p_scan.add_argument("--report", default=None, help="Save report to file")

    # --- verify ---
    p_verify = subparsers.add_parser("verify", help="Verify tool manifest integrity")
    p_verify.add_argument("manifest", help="Path to tool manifest JSON")

    # --- report ---
    p_report = subparsers.add_parser("report", help="Generate report from audit log")
    p_report.add_argument("--log", default="mcp-fortress_audit.jsonl")

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    if args.command == "proxy":
        cmd_proxy(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "report":
        cmd_report(args)


if __name__ == "__main__":
    main()
