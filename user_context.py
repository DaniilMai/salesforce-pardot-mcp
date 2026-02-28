"""
Per-request user context for multi-tenant tool routing.

The BearerAuthMiddleware sets the current API key on each request.
Tool functions read it to look up per-user OAuth credentials.
"""

from contextvars import ContextVar

# Set by BearerAuthMiddleware.on_request(), read by get_sf_client()/get_pardot_client()
current_api_key: ContextVar[str | None] = ContextVar("current_api_key", default=None)


def get_current_api_key() -> str | None:
    """Return the API key for the current request, or None if not set."""
    return current_api_key.get()
