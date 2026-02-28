"""
Bearer token authentication middleware for the MCP server.

Supports two authentication modes:
1. Self-service session tokens — generated via /login OAuth flow,
   validated against the encrypted token store.
2. Legacy API keys — validated against TEAM_API_KEYS env var
   (backward compatible, optional).

Includes audit logging (SHA-256 fingerprint) and per-key rate limiting.
"""

import hashlib
import os
import logging
import time
from collections import defaultdict

from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_http_headers
from user_context import current_api_key

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_REQUESTS_PER_MINUTE = 60

# ---------------------------------------------------------------------------
# Legacy API key loading (optional — only used when TEAM_API_KEYS is set)
# ---------------------------------------------------------------------------

_valid_keys: set[str] | None = None


def _load_api_keys() -> set[str]:
    """Parse TEAM_API_KEYS env var into a set of valid keys."""
    raw = os.environ.get("TEAM_API_KEYS", "")
    keys = {k.strip() for k in raw.split(",") if k.strip()}
    if keys:
        logger.info("Loaded %d legacy API key(s)", len(keys))
    return keys


def get_valid_keys() -> set[str]:
    """Lazy-load and cache valid API keys (parsed once, reused forever)."""
    global _valid_keys
    if _valid_keys is None:
        _valid_keys = _load_api_keys()
    return _valid_keys


# ---------------------------------------------------------------------------
# Rate limiting (sliding window, per-key)
# ---------------------------------------------------------------------------

_request_timestamps: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(token: str) -> None:
    """
    Enforce a sliding-window rate limit of MAX_REQUESTS_PER_MINUTE per key.
    Raises ValueError if the limit is exceeded.
    """
    fp = _key_fingerprint(token)
    now = time.monotonic()
    window = [t for t in _request_timestamps[fp] if now - t < 60]
    if len(window) >= MAX_REQUESTS_PER_MINUTE:
        logger.warning("Rate limit exceeded for key:%s", fp)
        raise ValueError(f"Rate limit exceeded: max {MAX_REQUESTS_PER_MINUTE} requests/minute")
    window.append(now)
    _request_timestamps[fp] = window


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _key_fingerprint(token: str) -> str:
    """Return first 8 hex chars of the SHA-256 hash of a key (for safe logging)."""
    return hashlib.sha256(token.encode()).hexdigest()[:8]


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class BearerAuthMiddleware(Middleware):
    """
    FastMCP middleware that gates every MCP request behind a bearer token.

    Accepts either:
    - A session token (from /login OAuth flow, stored in TokenStore)
    - A legacy API key (from TEAM_API_KEYS env var)

    After successful authentication:
    - Sets current_api_key ContextVar for per-user tool routing
    - Logs an audit entry with the key fingerprint and MCP method
    - Enforces per-key rate limiting (sliding window)
    """

    async def on_request(
        self,
        context: MiddlewareContext,
        call_next,
    ):
        # --- Skip auth for local development ---
        if os.environ.get("SKIP_AUTH", "").lower() in ("1", "true", "yes"):
            return await call_next(context)

        # --- Extract bearer token ---
        # FastMCP excludes "authorization" header by default — explicitly include it
        headers = get_http_headers(include={"authorization"}) or {}
        auth_header = headers.get("authorization", "")

        if not auth_header.lower().startswith("bearer "):
            logger.warning("Rejected request — missing or malformed Authorization header")
            raise ValueError("Unauthorized: missing Bearer token")

        token = auth_header.split(" ", 1)[1]

        # --- Try 1: session token (self-service OAuth) ---
        from token_store import get_token_store

        store = get_token_store()
        is_session_token = store is not None and store.has_tokens(token)

        if not is_session_token:
            # --- Try 2: legacy API key ---
            if token not in get_valid_keys():
                logger.warning("Rejected request — invalid token")
                raise ValueError("Unauthorized: invalid token")

        # --- Rate limiting ---
        _check_rate_limit(token)

        # --- Audit log ---
        logger.info(
            "Authorized — key:%s method:%s mode:%s",
            _key_fingerprint(token),
            context.method,
            "session" if is_session_token else "legacy",
        )

        # --- Set user context for per-user client routing ---
        token_var = current_api_key.set(token)
        try:
            return await call_next(context)
        finally:
            current_api_key.reset(token_var)
