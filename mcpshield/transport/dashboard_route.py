# MCP-Fortress — by Avoceous (https://github.com/Avoceous) | MIT License
"""
Dashboard route mixin — adds /dashboard to the ProxyServer FastAPI app.
Imported and wired in proxy.py.
"""

from __future__ import annotations

import pathlib

_DASHBOARD_HTML = pathlib.Path(__file__).parent / "dashboard.html"


def add_dashboard_route(app):
    """Register the /dashboard route on the given FastAPI app."""
    try:
        from fastapi.responses import HTMLResponse

        @app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
        async def dashboard():
            return HTMLResponse(_DASHBOARD_HTML.read_text(encoding="utf-8"))

        @app.get("/", response_class=HTMLResponse, include_in_schema=False)
        async def root_redirect():
            return HTMLResponse(
                '<meta http-equiv="refresh" content="0;url=/dashboard">',
                status_code=302,
            )

    except ImportError:
        pass  # fastapi not installed
