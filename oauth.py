"""
Self-service Salesforce OAuth 2.0 Web Server Flow.

Users visit /login in a browser, authenticate with their own Salesforce org,
and receive a session token to paste into Claude Desktop.  No admin-generated
API keys required.

GET  /login           — Redirect to Salesforce OAuth authorize URL (no auth)
GET  /oauth/callback  — Exchange authorization code, generate session token,
                         show HTML page with token + instructions
GET  /oauth/status    — Check connection status (Bearer session_token)
POST /oauth/revoke    — Remove session token (Bearer session_token)
"""

import hashlib
import html
import os
import time
import logging
import secrets
import urllib.parse

import httpx
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

from token_store import get_token_store, UserTokens

# ---------------------------------------------------------------------------
# Allowed Salesforce instance URL suffixes
# ---------------------------------------------------------------------------

_ALLOWED_SF_DOMAINS = (
    ".salesforce.com",
    ".force.com",
    ".salesforce.mil",
    ".cloudforce.com",
)


def _validate_instance_url(url: str) -> bool:
    """Check that instance_url is a valid Salesforce domain over HTTPS."""
    if not url.startswith("https://"):
        return False
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return False
    return any(host.endswith(d) for d in _ALLOWED_SF_DOMAINS)


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OAuth configuration from env vars
# ---------------------------------------------------------------------------

SF_OAUTH_CLIENT_ID = os.environ.get("SF_OAUTH_CLIENT_ID", "")
SF_OAUTH_CLIENT_SECRET = os.environ.get("SF_OAUTH_CLIENT_SECRET", "")
SF_OAUTH_REDIRECT_URI = os.environ.get("SF_OAUTH_REDIRECT_URI", "")
SF_OAUTH_LOGIN_URL = os.environ.get("SF_OAUTH_LOGIN_URL", "https://login.salesforce.com")

# ---------------------------------------------------------------------------
# CSRF protection: state -> created_at (no api_key mapping needed anymore)
# ---------------------------------------------------------------------------

_STATE_TTL_SECONDS = 600  # 10 minutes
_MAX_PENDING_STATES = 100

_pending_states: dict[str, float] = {}


def _cleanup_expired_states() -> None:
    """Remove expired pending states to prevent memory leak."""
    now = time.time()
    expired = [s for s, ts in _pending_states.items() if now - ts > _STATE_TTL_SECONDS]
    for s in expired:
        del _pending_states[s]


def _token_fingerprint(token: str) -> str:
    """Return first 8 hex chars of SHA-256 hash (for safe logging)."""
    return hashlib.sha256(token.encode()).hexdigest()[:8]


def _extract_session_token(request: Request) -> str | None:
    """Extract Bearer token from Authorization header (no validation)."""
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return None
    return auth_header.split(" ", 1)[1]


# ---------------------------------------------------------------------------
# /login — redirect to Salesforce OAuth (NO auth required)
# ---------------------------------------------------------------------------


async def oauth_login(request: Request) -> RedirectResponse:
    """Redirect the user to Salesforce OAuth authorize URL."""
    if not SF_OAUTH_CLIENT_ID or not SF_OAUTH_REDIRECT_URI:
        return JSONResponse(
            {"error": "OAuth not configured (SF_OAUTH_CLIENT_ID / SF_OAUTH_REDIRECT_URI missing)"},
            status_code=503,
        )

    _cleanup_expired_states()

    if len(_pending_states) >= _MAX_PENDING_STATES:
        return JSONResponse(
            {"error": "Too many pending authorization requests, try again later"},
            status_code=429,
        )

    state = secrets.token_urlsafe(32)
    _pending_states[state] = time.time()

    params = {
        "response_type": "code",
        "client_id": SF_OAUTH_CLIENT_ID,
        "redirect_uri": SF_OAUTH_REDIRECT_URI,
        "state": state,
        "scope": "api refresh_token pardot_api",
    }
    authorize_url = f"{SF_OAUTH_LOGIN_URL}/services/oauth2/authorize?{urllib.parse.urlencode(params)}"

    return RedirectResponse(url=authorize_url)


# ---------------------------------------------------------------------------
# /oauth/callback — exchange code for tokens, return HTML with session_token
# ---------------------------------------------------------------------------

_SUCCESS_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Connected to Salesforce</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #f5f5f5; display: flex; justify-content: center; align-items: center;
           min-height: 100vh; padding: 20px; }}
    .card {{ background: white; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1);
             max-width: 600px; width: 100%; padding: 40px; }}
    h1 {{ color: #1a1a1a; font-size: 24px; margin-bottom: 8px; }}
    .subtitle {{ color: #666; margin-bottom: 24px; }}
    .token-box {{ background: #f0f4f8; border: 1px solid #d0d7de; border-radius: 8px;
                   padding: 16px; margin: 16px 0; position: relative; }}
    .token-label {{ font-size: 12px; color: #666; text-transform: uppercase;
                     letter-spacing: 0.5px; margin-bottom: 8px; }}
    .token-value {{ font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 13px;
                     word-break: break-all; color: #1a1a1a; user-select: all; }}
    .copy-btn {{ background: #0070d2; color: white; border: none; border-radius: 6px;
                  padding: 10px 20px; font-size: 14px; cursor: pointer; margin-top: 12px;
                  width: 100%; }}
    .copy-btn:hover {{ background: #005bb5; }}
    .copy-btn.copied {{ background: #2e844a; }}
    .instructions {{ margin-top: 24px; }}
    .instructions h2 {{ font-size: 16px; color: #1a1a1a; margin-bottom: 12px; }}
    .instructions ol {{ padding-left: 20px; color: #444; }}
    .instructions li {{ margin-bottom: 8px; line-height: 1.5; }}
    code {{ background: #f0f4f8; padding: 2px 6px; border-radius: 4px;
            font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 13px; }}
    .config-block {{ background: #1e1e1e; color: #d4d4d4; border-radius: 8px;
                      padding: 16px; margin: 12px 0; font-family: 'SF Mono', Monaco, Consolas, monospace;
                      font-size: 12px; overflow-x: auto; white-space: pre; }}
    .instance {{ color: #666; font-size: 13px; margin-top: 16px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Connected to Salesforce</h1>
    <p class="subtitle">Your session token is ready. Copy it and add it to Claude Desktop.</p>

    <div class="token-box">
      <div class="token-label">Session Token</div>
      <div class="token-value" id="token">{session_token}</div>
    </div>
    <button class="copy-btn" id="copyBtn" onclick="copyToken()">Copy Token</button>

    <div class="instructions">
      <h2>Setup Instructions</h2>
      <ol>
        <li>Open Claude Desktop settings</li>
        <li>Go to <strong>Developer</strong> &rarr; <strong>Edit Config</strong></li>
        <li>Add (or update) the MCP server entry:</li>
      </ol>
      <div class="config-block">{{
  "mcpServers": {{
    "salesforce": {{
      "url": "{server_url}/sse",
      "headers": {{
        "Authorization": "Bearer {session_token}"
      }}
    }}
  }}
}}</div>
      <ol start="4">
        <li>Save and restart Claude Desktop</li>
      </ol>
    </div>

    <p class="instance">Connected org: <strong>{instance_url}</strong></p>
  </div>

  <script>
    function copyToken() {{
      const token = document.getElementById('token').textContent;
      navigator.clipboard.writeText(token).then(() => {{
        const btn = document.getElementById('copyBtn');
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => {{ btn.textContent = 'Copy Token'; btn.classList.remove('copied'); }}, 2000);
      }});
    }}
  </script>
</body>
</html>
"""

_ERROR_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Connection Failed</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #f5f5f5; display: flex; justify-content: center; align-items: center;
           min-height: 100vh; padding: 20px; }}
    .card {{ background: white; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1);
             max-width: 500px; width: 100%; padding: 40px; text-align: center; }}
    h1 {{ color: #c23934; font-size: 24px; margin-bottom: 12px; }}
    p {{ color: #666; line-height: 1.5; }}
    a {{ color: #0070d2; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Connection Failed</h1>
    <p>{error_message}</p>
    <p style="margin-top: 16px;"><a href="/login">Try again</a></p>
  </div>
</body>
</html>
"""


async def oauth_callback(request: Request) -> HTMLResponse:
    """Handle OAuth callback: exchange code, generate session_token, show HTML."""
    code = request.query_params.get("code")
    state = request.query_params.get("state")

    if not code or not state:
        return HTMLResponse(
            _ERROR_HTML.format(error_message="Missing authorization code. Please try again."),
            status_code=400,
        )

    created_at = _pending_states.pop(state, None)
    if created_at is None:
        return HTMLResponse(
            _ERROR_HTML.format(error_message="Invalid or expired session. Please try again."),
            status_code=400,
        )

    if time.time() - created_at > _STATE_TTL_SECONDS:
        return HTMLResponse(
            _ERROR_HTML.format(error_message="Session expired. Please try again."),
            status_code=400,
        )

    store = get_token_store()
    if not store:
        return HTMLResponse(
            _ERROR_HTML.format(error_message="Server misconfigured: ENCRYPTION_KEY not set."),
            status_code=503,
        )

    # Exchange authorization code for tokens
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{SF_OAUTH_LOGIN_URL}/services/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": SF_OAUTH_CLIENT_ID,
                "client_secret": SF_OAUTH_CLIENT_SECRET,
                "redirect_uri": SF_OAUTH_REDIRECT_URI,
            },
        )
        if resp.status_code != 200:
            logger.error("OAuth token exchange failed (HTTP %d)", resp.status_code)
            return HTMLResponse(
                _ERROR_HTML.format(error_message="Salesforce rejected the authorization. Please try again."),
                status_code=502,
            )

        token_data = resp.json()

    instance_url = token_data.get("instance_url", "")
    if not _validate_instance_url(instance_url):
        logger.error("OAuth returned invalid instance_url")
        return HTMLResponse(
            _ERROR_HTML.format(error_message="Invalid Salesforce instance URL returned."),
            status_code=502,
        )

    # Generate a cryptographically secure session token
    session_token = secrets.token_urlsafe(48)

    tokens = UserTokens(
        access_token=token_data["access_token"],
        refresh_token=token_data.get("refresh_token", ""),
        instance_url=instance_url,
        issued_at=time.time(),
        pardot_business_unit_id=None,
    )
    store.put(session_token, tokens)

    logger.info(
        "Session created: %s (instance: %s)",
        _token_fingerprint(session_token),
        instance_url,
    )

    # Build server URL for config example
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost:8000"))
    server_url = f"{scheme}://{host}"

    return HTMLResponse(
        _SUCCESS_HTML.format(
            session_token=html.escape(session_token),
            instance_url=html.escape(instance_url),
            server_url=html.escape(server_url),
        )
    )


# ---------------------------------------------------------------------------
# /oauth/status — check connection (requires Bearer session_token)
# ---------------------------------------------------------------------------


async def oauth_status(request: Request) -> JSONResponse:
    """Check whether the session token has a connected Salesforce account."""
    session_token = _extract_session_token(request)
    if not session_token:
        return JSONResponse({"error": "Bearer token required"}, status_code=401)

    store = get_token_store()
    if not store:
        return JSONResponse({"connected": False, "mode": "not_configured"})

    tokens = store.get(session_token)
    if tokens:
        return JSONResponse({
            "connected": True,
            "instance_url": tokens["instance_url"],
        })
    return JSONResponse({"connected": False})


# ---------------------------------------------------------------------------
# /oauth/revoke — remove session (requires Bearer session_token)
# ---------------------------------------------------------------------------


async def oauth_revoke(request: Request) -> JSONResponse:
    """Remove stored OAuth tokens for the given session token."""
    session_token = _extract_session_token(request)
    if not session_token:
        return JSONResponse({"error": "Bearer token required"}, status_code=401)

    store = get_token_store()
    if not store:
        return JSONResponse({"error": "Token storage not configured"}, status_code=503)

    removed = store.delete(session_token)
    logger.info("Session revoked: %s (found=%s)", _token_fingerprint(session_token), removed)
    return JSONResponse({"success": True, "was_connected": removed})
