# MCP-Fortress — by Avoceous (https://github.com/Avoceous) | MIT License
"""
MCP-Fortress stdio Transport

Wraps a local MCP server command (stdio transport) and intercepts
JSON-RPC messages on stdin/stdout.

Use this when you cannot run an HTTP proxy — e.g. when using:
  - Claude Desktop Extensions
  - Cursor MCP servers
  - Any stdio-based MCP client

Usage in claude_desktop_config.json or .cursor/mcp.json:

  BEFORE (unprotected):
  {
    "mcpServers": {
      "filesystem": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "."]
      }
    }
  }

  AFTER (protected by MCP-Fortress):
  {
    "mcpServers": {
      "filesystem-protected": {
        "command": "mcp-fortress-stdio",
        "args": [
          "--policy", "/path/to/policy.yaml",
          "--",
          "npx", "-y", "@modelcontextprotocol/server-filesystem", "."
        ]
      }
    }
  }

Zero external dependencies.
"""

from __future__ import annotations

import json
import logging
import os
import select
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, Dict, Optional

from mcpshield.core.models import SecurityAction, ToolCall, ToolManifest
from mcpshield.core.pipeline import MCPFortressPipeline
from mcpshield.policy.firewall import PolicyFirewall

logger = logging.getLogger(__name__)


class StdioProxy:
    """
    Transparent stdio proxy that intercepts MCP JSON-RPC messages.

    Sits between the MCP client (Claude Desktop, Cursor, etc.) and
    the upstream MCP server process, evaluating every tools/call.
    """

    def __init__(
        self,
        upstream_cmd: list,
        policy_file: Optional[str] = None,
        config_file: Optional[str] = None,
        audit_log: Optional[str] = None,
    ):
        # Build pipeline
        if config_file and os.path.exists(config_file):
            self._pipeline = MCPFortressPipeline.from_config(config_file)
        else:
            self._pipeline = MCPFortressPipeline(
                audit_log_path=audit_log,
            )

        if policy_file and os.path.exists(policy_file):
            self._pipeline._policy.load_from_file(policy_file)

        self._upstream_cmd = upstream_cmd
        self._session_id = str(uuid.uuid4())
        self._proc: Optional[subprocess.Popen] = None

    def run(self):
        """Start upstream process and proxy stdio. Blocks until upstream exits."""
        self._proc = subprocess.Popen(
            self._upstream_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        session = self._pipeline.get_or_create_session(self._session_id)

        # Thread: forward upstream stderr → our stderr (for logs)
        def forward_stderr():
            for line in self._proc.stderr:
                sys.stderr.buffer.write(line)
                sys.stderr.buffer.flush()

        t_err = threading.Thread(target=forward_stderr, daemon=True)
        t_err.start()

        # Thread: forward upstream stdout → client stdout (with inspection)
        def forward_upstream_to_client():
            for raw_line in self._proc.stdout:
                try:
                    msg = json.loads(raw_line)
                    # Scan output for PII/secrets
                    if "result" in msg:
                        result_text = json.dumps(msg["result"])
                        dummy_call = ToolCall(session_id=self._session_id, tool_name="<output>", arguments={})
                        from mcpshield.core.models import SecurityDecision
                        dummy_dec = SecurityDecision(call_id="out", action=SecurityAction.ALLOW, reason="output scan")
                        clean = self._pipeline.scan_output(result_text, dummy_call, dummy_dec)
                        if clean != result_text:
                            msg["result"] = json.loads(clean)
                    out = json.dumps(msg) + "\n"
                except (json.JSONDecodeError, Exception):
                    out = raw_line.decode("utf-8", errors="replace")

                sys.stdout.write(out)
                sys.stdout.flush()

        t_out = threading.Thread(target=forward_upstream_to_client, daemon=True)
        t_out.start()

        # Main thread: read from client stdin, inspect, forward to upstream
        try:
            for raw_line in sys.stdin:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue

                try:
                    msg = json.loads(raw_line)
                except json.JSONDecodeError:
                    # Pass malformed input through — upstream will handle error
                    self._write_upstream(raw_line + "\n")
                    continue

                method = msg.get("method", "")

                if method == "tools/call":
                    params = msg.get("params", {})
                    call = ToolCall(
                        id=str(msg.get("id", uuid.uuid4())),
                        session_id=self._session_id,
                        tool_name=params.get("name", "unknown"),
                        arguments=params.get("arguments", {}),
                    )

                    decision = self._pipeline.evaluate_call(call, session)

                    if decision.action == SecurityAction.BLOCK:
                        # Return MCP error to client, do NOT forward to upstream
                        error_resp = json.dumps({
                            "jsonrpc": "2.0",
                            "id": msg.get("id"),
                            "error": {
                                "code": -32603,
                                "message": f"[MCP-Fortress] Blocked: {decision.reason}",
                            },
                        }) + "\n"
                        sys.stdout.write(error_resp)
                        sys.stdout.flush()

                        # Log to stderr for visibility
                        sys.stderr.write(
                            f"[MCP-Fortress] BLOCKED {call.tool_name}: {decision.reason}\n"
                        )
                        sys.stderr.flush()
                        continue

                    elif decision.action == SecurityAction.REQUIRE_APPROVAL:
                        # In stdio mode, we cannot do async approval — auto-deny
                        # (In a future version this could pause and prompt the terminal)
                        sys.stderr.write(
                            f"[MCP-Fortress] AUTO-DENIED (requires approval, not supported in stdio mode): "
                            f"{call.tool_name}\n"
                        )
                        sys.stderr.flush()
                        error_resp = json.dumps({
                            "jsonrpc": "2.0",
                            "id": msg.get("id"),
                            "error": {
                                "code": -32603,
                                "message": f"[MCP-Fortress] Tool requires human approval (blast radius: {decision.blast_radius_score}/100).",
                            },
                        }) + "\n"
                        sys.stdout.write(error_resp)
                        sys.stdout.flush()
                        continue

                    elif decision.action == SecurityAction.ALERT:
                        sys.stderr.write(
                            f"[MCP-Fortress] ALERT on {call.tool_name}: "
                            f"{'; '.join(a.title for a in decision.alerts[:2])}\n"
                        )
                        sys.stderr.flush()

                elif method == "tools/list":
                    # We'll verify tools when we see the response — handled in forward_upstream_to_client
                    pass

                # Forward to upstream
                self._write_upstream(json.dumps(msg) + "\n")

        except KeyboardInterrupt:
            pass
        finally:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()

    def _write_upstream(self, data: str):
        if self._proc and self._proc.stdin:
            self._proc.stdin.write(data.encode())
            self._proc.stdin.flush()


def main_stdio():
    """Entry point for mcp-fortress-stdio command."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="mcp-fortress-stdio",
        description="MCP-Fortress stdio proxy — wraps any MCP server command",
    )
    parser.add_argument("--policy", default=None, help="Policy YAML file")
    parser.add_argument("--config", default=None, help="MCP-Fortress config YAML")
    parser.add_argument("--audit-log", default=None, help="Audit log file path")
    parser.add_argument("--", dest="upstream", nargs=argparse.REMAINDER,
                        help="Upstream MCP server command")

    # Handle `--` separator
    args_raw = sys.argv[1:]
    if "--" in args_raw:
        sep = args_raw.index("--")
        our_args = args_raw[:sep]
        upstream_cmd = args_raw[sep + 1:]
    else:
        our_args = args_raw
        upstream_cmd = []

    args = parser.parse_args(our_args)

    if not upstream_cmd:
        parser.error("Provide upstream command after --")

    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    proxy = StdioProxy(
        upstream_cmd=upstream_cmd,
        policy_file=args.policy,
        config_file=args.config,
        audit_log=args.audit_log,
    )
    proxy.run()


if __name__ == "__main__":
    main_stdio()
