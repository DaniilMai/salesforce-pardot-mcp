"""
Salesforce + Pardot Remote MCP Server

Entry point that wires together authentication middleware, Salesforce and
Pardot tools, and a health-check endpoint. Runs over SSE transport for
Claude Desktop compatibility.

Usage:
    python server.py          # starts on PORT (default 8000)
    docker build -t sf-mcp .  # containerize for Railway
"""

import os
import logging

from dotenv import load_dotenv
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from auth import BearerAuthMiddleware
from tools import ALL_TOOLS
from oauth import oauth_login, oauth_callback, oauth_status, oauth_revoke

# Load .env for local development (no-op if .env is absent)
# Use explicit path so it works regardless of working directory (e.g. stdio via Claude Desktop)
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="Salesforce-Pardot-MCP",
    instructions=(
        "MCP server providing Salesforce CRM and Pardot "
        "(Marketing Cloud Account Engagement) tools.\n\n"
        "Each user connects their own Salesforce account via OAuth. "
        "Visit /login in a browser to connect, then use the session "
        "token in Claude Desktop.\n\n"
        "Use sf_* tools for Salesforce operations — SOQL queries, "
        "lead/contact CRUD, pipeline reporting, and activity history "
        "(tasks and events).\n\n"
        "Use pardot_* tools for Pardot operations — prospects, "
        "campaigns, lists, forms, visitor activities, emails, "
        "and lifecycle history."
    ),
)

# ---------------------------------------------------------------------------
# Auth middleware
# ---------------------------------------------------------------------------

mcp.add_middleware(BearerAuthMiddleware())

# ---------------------------------------------------------------------------
# Register all tools
# ---------------------------------------------------------------------------

for tool_fn in ALL_TOOLS:
    mcp.add_tool(tool_fn)

logger.info("Registered %d MCP tools", len(ALL_TOOLS))

# ---------------------------------------------------------------------------
# Health endpoint (used by Railway health checks)
# ---------------------------------------------------------------------------


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# Self-service OAuth endpoints
# ---------------------------------------------------------------------------


@mcp.custom_route("/login", methods=["GET"])
async def _login(request: Request):
    return await oauth_login(request)


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def _oauth_callback(request: Request):
    return await oauth_callback(request)


@mcp.custom_route("/oauth/status", methods=["GET"])
async def _oauth_status(request: Request):
    return await oauth_status(request)


@mcp.custom_route("/oauth/revoke", methods=["POST"])
async def _oauth_revoke(request: Request):
    return await oauth_revoke(request)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    transport = os.environ.get("MCP_TRANSPORT", "sse").lower()

    if transport == "stdio":
        # --- stdio mode: Claude Desktop runs this process directly ---
        logger.info("Starting Salesforce-Pardot MCP server (stdio)")
        mcp.run(transport="stdio")
    else:
        # --- SSE mode: remote deployment (Railway) or local dev ---
        port = int(os.environ.get("PORT", 8000))
        ssl_certfile = os.environ.get("SSL_CERTFILE")
        ssl_keyfile = os.environ.get("SSL_KEYFILE")

        if ssl_certfile and ssl_keyfile:
            logger.info("Starting Salesforce-Pardot MCP server on port %d (SSE + HTTPS)", port)
            mcp.run(
                transport="sse",
                host="0.0.0.0",
                port=port,
                uvicorn_config={"ssl_certfile": ssl_certfile, "ssl_keyfile": ssl_keyfile},
            )
        else:
            logger.info("Starting Salesforce-Pardot MCP server on port %d (SSE)", port)
            mcp.run(transport="sse", host="0.0.0.0", port=port)
