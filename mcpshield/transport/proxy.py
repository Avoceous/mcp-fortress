# MCP-Fortress — by Avoceous (https://github.com/Avoceous) | MIT License
"""
MCP-Fortress Proxy Server

A transparent HTTP/SSE/WebSocket proxy that sits between AI agents and any
upstream MCP server. Intercepts all JSON-RPC tool calls, runs them through
the security pipeline, and either forwards them or blocks/holds them.

Supports:
  - Streamable HTTP (MCP 2025-11-05 spec)
  - Server-Sent Events (SSE) transport
  - stdio passthrough for local MCP servers

Requires: fastapi, uvicorn, httpx
Install:  pip install mcp-fortress[proxy]
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import time
import uuid
from typing import Any, AsyncIterator, Dict, Optional

logger = logging.getLogger(__name__)

try:
    import httpx
    import uvicorn
    from fastapi import FastAPI, HTTPException, Request, Response
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, StreamingResponse
    _PROXY_AVAILABLE = True
except ImportError:
    _PROXY_AVAILABLE = False

from mcpshield.core.models import SecurityAction, ToolCall
from mcpshield.core.pipeline import MCPFortressPipeline


class ProxyServer:
    """
    Transparent MCP security proxy.

    Intercepts every JSON-RPC request, evaluates it through MCPFortressPipeline,
    then either:
      - Forwards to upstream (ALLOW / ALERT)
      - Holds for approval (REQUIRE_APPROVAL)
      - Returns a security error (BLOCK)
      - Redacts the upstream response (REDACT)

    Usage:
        server = ProxyServer(upstream="http://localhost:3000", port=8100)
        server.run()
    """

    def __init__(
        self,
        upstream: str,
        host: str = "127.0.0.1",
        port: int = 8100,
        config: Optional[str] = None,
        policy: Optional[str] = None,
    ):
        if not _PROXY_AVAILABLE:
            raise ImportError(
                "Proxy requires: pip install mcp-fortress[proxy]\n"
                "  (installs fastapi, uvicorn, httpx)"
            )

        self._upstream = upstream.rstrip("/")
        self._host = host
        self._port = port

        # Build pipeline from config or defaults
        if config and os.path.exists(config):
            self._pipeline = MCPFortressPipeline.from_config(config)
        else:
            self._pipeline = MCPFortressPipeline()

        # Override policy if specified
        if policy:
            self._pipeline._policy.load_from_file(policy)

        # Pending approval queue: request_id -> (call, event)
        self._pending: Dict[str, Dict] = {}

        self._app = self._build_app()

    # ------------------------------------------------------------------
    # FastAPI app
    # ------------------------------------------------------------------

    def _build_app(self) -> "FastAPI":
        app = FastAPI(
            title="MCP-Fortress Proxy",
            description="Security proxy for MCP servers",
            version="0.1.0",
            docs_url="/docs",
        )

        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # ---- MCP JSON-RPC endpoint (Streamable HTTP) ----
        @app.post("/mcp")
        async def mcp_endpoint(request: Request):
            return await self._handle_mcp_request(request)

        @app.get("/mcp")
        async def mcp_get_endpoint(request: Request):
            # SSE transport: GET opens the event stream
            return await self._handle_sse_stream(request)

        # ---- Catch-all proxy for other MCP paths ----
        @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
        async def catch_all(request: Request, path: str):
            if path.startswith("api/v1") or path == "dashboard" or path == "":  # reserved routes
                raise HTTPException(404, "Not found")
            return await self._proxy_passthrough(request, path)

        # ---- Management API ----
        @app.get("/api/v1/health")
        async def health():
            return {"status": "ok", "version": "0.1.0", "upstream": self._upstream}

        @app.get("/api/v1/sessions")
        async def sessions():
            return {
                sid: {
                    "session_id": s.session_id,
                    "source_ip": s.source_ip,
                    "total_calls": s.total_calls,
                    "blocked_calls": s.blocked_calls,
                    "risk_score": round(s.risk_score, 3),
                    "tags": s.tags,
                    "alerts": len(s.alert_history),
                }
                for sid, s in self._pipeline._sessions.items()
            }

        @app.get("/api/v1/alerts")
        async def alerts():
            all_alerts = []
            for s in self._pipeline._sessions.values():
                for a in s.alert_history[-20:]:
                    all_alerts.append(a.to_dict())
            all_alerts.sort(key=lambda x: x["timestamp"], reverse=True)
            return all_alerts[:100]

        @app.get("/api/v1/tools")
        async def tools():
            return {
                name: {
                    "name": m.name,
                    "tool_class": m.tool_class,
                    "destructiveness": m.destructiveness,
                    "trusted": m.trusted,
                    "external_network": m.external_network,
                    "data_scope": m.data_scope,
                }
                for name, m in self._pipeline._tools.items()
            }

        @app.get("/api/v1/pending")
        async def pending():
            return list(self._pending.values())

        @app.post("/api/v1/approve/{request_id}")
        async def approve(request_id: str):
            if request_id not in self._pending:
                raise HTTPException(404, "Pending request not found")
            self._pending[request_id]["approved"] = True
            self._pending[request_id]["resolved"] = True
            self._pending[request_id]["event"].set()
            return {"status": "approved", "request_id": request_id}

        @app.post("/api/v1/deny/{request_id}")
        async def deny(request_id: str):
            if request_id not in self._pending:
                raise HTTPException(404, "Pending request not found")
            self._pending[request_id]["approved"] = False
            self._pending[request_id]["resolved"] = True
            self._pending[request_id]["event"].set()
            return {"status": "denied", "request_id": request_id}

        @app.post("/api/v1/policy/reload")
        async def reload_policy():
            self._pipeline._policy.maybe_hot_reload()
            return {"status": "reloaded", "rules": self._pipeline._policy.rule_count}

        return app

    # ------------------------------------------------------------------
    # MCP Request handling
    # ------------------------------------------------------------------

    async def _handle_mcp_request(self, request: Request) -> Response:
        """Handle a single MCP JSON-RPC POST request."""
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(400, "Invalid JSON body")

        source_ip = request.client.host if request.client else "unknown"
        session_id = request.headers.get("x-session-id") or request.headers.get("mcp-session-id") or source_ip

        # Only intercept tool calls; pass everything else through
        method = body.get("method", "")
        if method == "tools/call":
            return await self._evaluate_and_forward(body, session_id, source_ip, request)
        elif method == "tools/list":
            # After getting tool list from upstream, verify integrity
            response = await self._forward_raw(request, body)
            await self._verify_tools_from_response(response)
            return response

        # All other methods (initialize, resources/*, prompts/*): pass through
        return await self._forward_raw(request, body)

    async def _evaluate_and_forward(
        self,
        body: Dict,
        session_id: str,
        source_ip: str,
        request: Request,
    ) -> Response:
        """Evaluate a tools/call through the security pipeline."""
        params = body.get("params", {})
        tool_name = params.get("name", "unknown")
        arguments = params.get("arguments", {})
        call_id = str(body.get("id", uuid.uuid4()))

        call = ToolCall(
            id=call_id,
            session_id=session_id,
            tool_name=tool_name,
            arguments=arguments,
            source_ip=source_ip,
            raw_request=body,
        )

        session = self._pipeline.get_or_create_session(
            session_id, source_ip=source_ip
        )

        decision = self._pipeline.evaluate_call(call, session)

        # Log the decision
        logger.info(
            "SHIELD [%s] %s -> %s (blast=%s, alerts=%d, %.1fms)",
            session_id[:8], tool_name, decision.action.value,
            decision.blast_radius_score, len(decision.alerts), decision.duration_ms
        )

        if decision.action == SecurityAction.BLOCK:
            session.blocked_calls += 1
            return self._mcp_error_response(
                call_id,
                code=-32603,
                message=f"[MCP-Fortress] Tool call blocked: {decision.reason}",
                data={"alerts": [a.to_dict() for a in decision.alerts[:3]]},
            )

        if decision.action == SecurityAction.REQUIRE_APPROVAL:
            approved = await self._request_approval(call, decision)
            if not approved:
                session.blocked_calls += 1
                return self._mcp_error_response(
                    call_id,
                    code=-32603,
                    message="[MCP-Fortress] Tool call denied by security review.",
                )

        # Forward to upstream
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.post(
                    f"{self._upstream}/mcp",
                    json=body,
                    headers={k: v for k, v in request.headers.items()
                             if k.lower() not in ("host", "content-length")},
                )
                upstream_body = resp.json()
            except httpx.RequestError as e:
                raise HTTPException(502, f"Upstream MCP server unreachable: {e}")

        # Scan output
        if "result" in upstream_body:
            result_text = json.dumps(upstream_body["result"])
            clean = self._pipeline.scan_output(result_text, call, decision)
            if clean != result_text:
                upstream_body["result"] = json.loads(clean)
                upstream_body.setdefault("_mcp-fortress", {})["output_redacted"] = True

        # Attach shield metadata
        upstream_body.setdefault("_mcp-fortress", {}).update({
            "decision": decision.action.value,
            "blast_radius": decision.blast_radius_score,
        })

        return JSONResponse(upstream_body, status_code=200)

    async def _request_approval(self, call: ToolCall, decision) -> bool:
        """Hold a tool call pending human approval (via /api/v1/approve/{id})."""
        request_id = str(uuid.uuid4())
        event = asyncio.Event()

        self._pending[request_id] = {
            "request_id": request_id,
            "tool_name": call.tool_name,
            "arguments": call.arguments,
            "blast_radius": decision.blast_radius_score,
            "reason": decision.reason,
            "session_id": call.session_id,
            "timestamp": time.time(),
            "approved": False,
            "resolved": False,
            "event": event,
        }

        logger.warning(
            "SHIELD: Holding tool call '%s' for approval (id=%s). "
            "Approve: POST /api/v1/approve/%s",
            call.tool_name, request_id, request_id
        )

        # Wait up to 5 minutes for approval
        try:
            await asyncio.wait_for(event.wait(), timeout=300.0)
        except asyncio.TimeoutError:
            logger.warning("SHIELD: Approval timeout for request %s — denying.", request_id)
            self._pending.pop(request_id, None)
            return False

        approved = self._pending.pop(request_id, {}).get("approved", False)
        return approved

    async def _verify_tools_from_response(self, response: Response):
        """Parse a tools/list response and verify tool integrity."""
        try:
            if hasattr(response, "body"):
                body = json.loads(response.body)
            else:
                return
            tools_raw = body.get("result", {}).get("tools", [])
            if not tools_raw:
                return

            from mcpshield.core.models import ToolManifest
            manifests = [
                ToolManifest(
                    name=t.get("name", "unknown"),
                    description=t.get("description", ""),
                    input_schema=t.get("inputSchema", {}),
                )
                for t in tools_raw
            ]
            alerts = self._pipeline.verify_tools(manifests)
            for alert in alerts:
                logger.warning("TDIV: %s — %s", alert.title, alert.description[:80])
        except Exception as e:
            logger.debug("Could not verify tools from response: %s", e)

    async def _forward_raw(self, request: Request, body: Any) -> Response:
        """Forward a request to upstream without inspection."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.post(
                    f"{self._upstream}/mcp",
                    json=body,
                    headers={k: v for k, v in request.headers.items()
                             if k.lower() not in ("host", "content-length")},
                )
                return Response(
                    content=resp.content,
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    media_type="application/json",
                )
            except httpx.RequestError as e:
                raise HTTPException(502, f"Upstream unreachable: {e}")

    async def _proxy_passthrough(self, request: Request, path: str) -> Response:
        """Pass non-MCP requests directly to upstream."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                body = await request.body()
                resp = await client.request(
                    method=request.method,
                    url=f"{self._upstream}/{path}",
                    content=body,
                    headers={k: v for k, v in request.headers.items()
                             if k.lower() not in ("host", "content-length")},
                )
                return Response(
                    content=resp.content,
                    status_code=resp.status_code,
                    media_type=resp.headers.get("content-type", "application/octet-stream"),
                )
            except httpx.RequestError as e:
                raise HTTPException(502, f"Upstream unreachable: {e}")

    async def _handle_sse_stream(self, request: Request) -> Response:
        """Proxy SSE streams (MCP SSE transport)."""
        source_ip = request.client.host if request.client else "unknown"

        async def event_generator() -> AsyncIterator[str]:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream("GET", f"{self._upstream}/mcp",
                                         headers=dict(request.headers)) as resp:
                    async for line in resp.aiter_lines():
                        yield line + "\n"

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    def _mcp_error_response(self, call_id: Any, code: int, message: str, data: Any = None) -> Response:
        body: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": call_id,
            "error": {"code": code, "message": message},
        }
        if data:
            body["error"]["data"] = data
        return JSONResponse(body, status_code=200)  # MCP errors use HTTP 200

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self):
        """Start the proxy server (blocking)."""
        uvicorn.run(
            self._app,
            host=self._host,
            port=self._port,
            log_level="info",
            access_log=True,
        )

    async def run_async(self):
        """Start the proxy server (async, for embedding)."""
        config = uvicorn.Config(
            self._app,
            host=self._host,
            port=self._port,
            log_level="info",
        )
        server = uvicorn.Server(config)
        await server.serve()
