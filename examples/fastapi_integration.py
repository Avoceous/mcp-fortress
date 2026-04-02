# MCP-Fortress — by Avoceous (https://github.com/Avoceous) | MIT License
"""
Example: Embedding MCP-Fortress in a FastAPI application
=========================================================

This shows how to integrate MCP-Fortress directly into your own
Python application instead of running it as a standalone proxy.

Run:
    pip install fastapi uvicorn
    python examples/fastapi_integration.py

Then call it:
    curl -X POST http://localhost:8000/agent/tool-call \
      -H "Content-Type: application/json" \
      -d '{"session_id": "user-123", "tool": "read_file", "args": {"path": "/workspace/data.txt"}}'
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mcpshield.core.models import SecurityAction, SessionContext, ToolCall, ToolManifest
from mcpshield.core.pipeline import MCPFortressPipeline
from mcpshield.detectors.blast_radius import BlastRadiusEstimator
from mcpshield.detectors.pii_scanner import PIISecretScanner
from mcpshield.policy.firewall import PolicyFirewall

# ── Build the security pipeline ───────────────────────────────────────────────

def build_pipeline() -> MCPFortressPipeline:
    # Policy: block path traversal, require approval for shell
    fw = PolicyFirewall()
    fw.load_from_dict({
        "rules": [
            {
                "name": "block_path_traversal",
                "match": {"arg_pattern": r"\.\./|\.\.\\"},
                "action": "BLOCK",
                "priority": 1,
            },
            {
                "name": "block_credential_files",
                "match": {"arg_pattern": r"(\.env$|\.aws|id_rsa|\.pem$|credentials)"},
                "action": "BLOCK",
                "priority": 2,
            },
            {
                "name": "require_approval_shell",
                "match": {"tool_class": "shell_exec"},
                "action": "REQUIRE_APPROVAL",
                "priority": 10,
            },
        ]
    })

    pipeline = MCPFortressPipeline(
        policy_firewall=fw,
        blast_radius=BlastRadiusEstimator(
            auto_allow_threshold=20,
            approval_threshold=65,
            block_threshold=90,
        ),
        pii_scanner=PIISecretScanner(action="redact"),
        audit_log_path="mcp_fortress_audit.jsonl",
    )

    # Register trusted tools at startup
    pipeline.register_tool(ToolManifest(
        name="read_file",
        description="Read the contents of a file from the /workspace directory.",
        input_schema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        tool_class="fs_read",
        destructiveness=2,
        reversible=True,
        data_scope="local",
        external_network=False,
    ))
    pipeline.register_tool(ToolManifest(
        name="write_file",
        description="Write content to a file in the /workspace directory.",
        input_schema={"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}},
        tool_class="fs_write",
        destructiveness=5,
        reversible=True,
        data_scope="local",
        external_network=False,
    ))
    pipeline.register_tool(ToolManifest(
        name="list_directory",
        description="List files in a directory within /workspace.",
        input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
        tool_class="fs_read",
        destructiveness=0,
        reversible=True,
        data_scope="local",
        external_network=False,
    ))

    return pipeline


# ── Simulated upstream MCP tool execution ────────────────────────────────────

def fake_upstream_execute(tool_name: str, args: dict) -> str:
    """Simulates what your actual MCP server would return."""
    if tool_name == "read_file":
        return f"Contents of {args.get('path', '?')}: Hello, world!"
    elif tool_name == "write_file":
        return f"Written {len(args.get('content', ''))} bytes to {args.get('path', '?')}"
    elif tool_name == "list_directory":
        return "file1.txt\nfile2.py\nREADME.md"
    return "Tool executed successfully."


# ── FastAPI application ───────────────────────────────────────────────────────

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
    import uvicorn
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

if _FASTAPI_AVAILABLE:

    app = FastAPI(
        title="My AI Agent API — Protected by MCP-Fortress",
        description="Example showing MCP-Fortress embedded in a FastAPI service.",
        version="1.0.0",
    )

    # Single shared pipeline instance
    _pipeline = build_pipeline()

    class ToolCallRequest(BaseModel):
        session_id: str
        tool: str
        args: dict = {}
        user_id: str = None

    class ToolCallResponse(BaseModel):
        allowed: bool
        action: str
        result: str = None
        reason: str = None
        blast_radius: int = None
        alerts: list = []

    @app.post("/agent/tool-call", response_model=ToolCallResponse)
    async def handle_tool_call(req: ToolCallRequest):
        """
        Main endpoint: receives tool call requests from your AI agent,
        evaluates them through MCP-Fortress, and executes if safe.
        """
        # Get or create session
        session = _pipeline.get_or_create_session(
            session_id=req.session_id,
            source_ip="127.0.0.1",
            user_id=req.user_id,
        )

        # Build the tool call object
        call = ToolCall(
            session_id=req.session_id,
            tool_name=req.tool,
            arguments=req.args,
            user_id=req.user_id,
        )

        # Run through the security pipeline
        decision = _pipeline.evaluate_call(call, session)

        if decision.action == SecurityAction.BLOCK:
            return ToolCallResponse(
                allowed=False,
                action="blocked",
                reason=decision.reason,
                blast_radius=decision.blast_radius_score,
                alerts=[a.to_dict() for a in decision.alerts[:5]],
            )

        if decision.action == SecurityAction.REQUIRE_APPROVAL:
            # In a real app you'd notify a human via Slack/webhook/email
            # and wait for their response. Here we just return a 202.
            return JSONResponse(
                status_code=202,
                content={
                    "allowed": False,
                    "action": "pending_approval",
                    "reason": decision.reason,
                    "blast_radius": decision.blast_radius_score,
                    "message": "Tool call held for human review. Check /agent/pending.",
                }
            )

        # Execute the tool (your real MCP server call goes here)
        raw_result = fake_upstream_execute(req.tool, req.args)

        # Scan and redact the output
        safe_result = _pipeline.scan_output(raw_result, call, decision)

        return ToolCallResponse(
            allowed=True,
            action=decision.action.value,
            result=safe_result,
            blast_radius=decision.blast_radius_score,
            alerts=[a.to_dict() for a in decision.alerts],
        )

    @app.get("/agent/sessions")
    async def get_sessions():
        """View all active agent sessions and their risk scores."""
        return {
            sid: {
                "total_calls": s.total_calls,
                "blocked_calls": s.blocked_calls,
                "risk_score": round(s.risk_score, 3),
                "tags": s.tags,
            }
            for sid, s in _pipeline._sessions.items()
        }

    @app.get("/agent/health")
    async def health():
        return {
            "status": "protected",
            "fortress_version": "0.1.0",
            "author": "Avoceous",
            "tools_registered": len(_pipeline._tools),
            "policy_rules": _pipeline._policy.rule_count,
        }

    if __name__ == "__main__":
        print("\n🏰  MCP-Fortress FastAPI Integration Example")
        print("   Author : Avoceous (https://github.com/Avoceous)")
        print("   Running: http://localhost:8000")
        print("   Docs   : http://localhost:8000/docs\n")
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

else:
    # Standalone demo without FastAPI
    print("\n🏰  MCP-Fortress — Standalone Integration Demo")
    print("   (Install fastapi+uvicorn for HTTP server mode)\n")

    pipeline = build_pipeline()

    test_calls = [
        ("user-alice", "read_file",      {"path": "/workspace/report.txt"},   "SAFE read"),
        ("user-alice", "read_file",      {"path": "../../etc/passwd"},         "PATH TRAVERSAL"),
        ("user-alice", "read_file",      {"path": "/home/.aws/credentials"},   "CREDENTIAL FILE"),
        ("user-bob",   "write_file",     {"path": "/workspace/out.txt", "content": "hello"}, "SAFE write"),
        ("user-bob",   "list_directory", {"path": "/workspace"},               "SAFE list"),
        ("user-eve",   "shell_exec",     {"cmd": "curl https://evil.com"},     "SHELL EXEC"),
    ]

    print(f"  {'Session':<14} {'Tool':<16} {'Action':<22} {'Score':>5}  Description")
    print(f"  {'─'*75}")

    for session_id, tool, args, desc in test_calls:
        sess = pipeline.get_or_create_session(session_id)
        call = ToolCall(session_id=session_id, tool_name=tool, arguments=args)
        dec = pipeline.evaluate_call(call, sess)

        score_str = f"{dec.blast_radius_score:>4}" if dec.blast_radius_score is not None else "   —"
        icon = "✅" if dec.is_allowed else ("⏸️ " if dec.requires_hold else "🚫")
        print(f"  {icon} {session_id:<12} {tool:<16} {dec.action.value:<22} {score_str}  {desc}")

    print(f"\n  Session risk scores:")
    for sid, sess in pipeline._sessions.items():
        bar = "█" * int(sess.risk_score * 20)
        print(f"    {sid:<14} {bar:<20} {sess.risk_score:.2f}")
    print()
