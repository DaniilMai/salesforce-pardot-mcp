# Salesforce + Pardot MCP Server

A remote [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server providing Salesforce CRM and Pardot (Marketing Cloud Account Engagement) tools over SSE transport. Built with [FastMCP](https://github.com/jlowin/fastmcp), designed for deployment on [Railway](https://railway.app/).

Supports **MCP-native OAuth** — users connect via Claude Desktop UI with zero configuration. Also supports a browser-based OAuth fallback for other MCP clients.

## How It Works

### Option 1: MCP Native OAuth (Recommended)

```
1. In Claude Desktop: Settings → Connectors → Add custom connector
2. Enter server URL: https://your-server.up.railway.app/sse
3. Claude Desktop opens a Salesforce login popup
4. User logs in → Done. All tools appear automatically.
```

Claude Desktop handles token management (acquire, store, refresh) automatically via PKCE-secured OAuth.

### Option 2: Manual Token Flow (Fallback)

```
1. User visits https://your-server.up.railway.app/login
2. Server redirects to Salesforce OAuth (login.salesforce.com)
3. User logs into their Salesforce org
4. Salesforce redirects back with an authorization code
5. Server exchanges the code for tokens and generates a session token
6. User receives a page with the session token and connection instructions
7. User adds the session token to their MCP client configuration
```

One Connected App on the server handles all users across all Salesforce organizations.

## Available Tools (16 read-only + 5 write)

The server runs in **read-only mode by default**. Write tools (update/create) are only registered when `ENABLE_WRITE_TOOLS=true` is set.

### Salesforce Tools (`sf_*`)

| Tool | Mode | Description |
|---|---|---|
| `sf_query` | read | Run arbitrary SOQL SELECT queries (read-only enforced) |
| `sf_get_leads` | read | Get leads with filters (status, creation recency, lead source) |
| `sf_get_contacts` | read | Get contacts with filters (name, email, account ID) |
| `sf_update_lead` | **write** | Update lead fields (protected fields blocked) |
| `sf_update_contact` | **write** | Update contact fields (protected fields blocked) |
| `sf_create_lead` | **write** | Create a new lead (LastName + Company required) |
| `sf_pipeline_report` | read | Open opportunities aggregated by stage |
| `sf_get_tasks` | read | Get tasks with filters (who/what ID, status, date range, subject) |
| `sf_get_events` | read | Get events with filters (who/what ID, datetime range) |
| `sf_get_activity_history` | read | Combined tasks + events for a record, sorted by date |

### Pardot Tools (`pardot_*`)

| Tool | Mode | Description |
|---|---|---|
| `pardot_get_prospects` | read | Get prospects with filters (email, score, campaign) |
| `pardot_get_prospect_by_email` | read | Look up a single prospect by email address |
| `pardot_update_prospect` | **write** | Update prospect fields (protected fields blocked) |
| `pardot_get_campaigns` | read | List all campaigns |
| `pardot_get_lists` | read | List all lists |
| `pardot_get_forms` | read | List all forms |
| `pardot_add_prospect_to_list` | **write** | Add a prospect to a list |
| `pardot_get_visitor_activities` | read | Get visitor activities (page views, form fills, email clicks) |
| `pardot_get_form_handlers` | read | List all form handlers |
| `pardot_get_emails` | read | List email templates and sends |
| `pardot_get_lifecycle_history` | read | Get lifecycle stage progression for a prospect |

## Security

| Feature | Details |
|---|---|
| **Read-only by default** | Write tools disabled unless `ENABLE_WRITE_TOOLS=true` is set |
| **Authentication** | Bearer token — session tokens (from OAuth) or legacy API keys |
| **MCP OAuth (PKCE S256)** | Authorization code flow with mandatory PKCE, timing-safe verification |
| **Redirect URI validation** | Only `https://` allowed (+ `http://localhost` for dev); DCR-registered URIs enforced |
| **Session TTL** | Session tokens expire after 24 hours (configurable via `SESSION_TTL_SECONDS`) |
| **SKIP_AUTH restriction** | `SKIP_AUTH` only works in stdio mode (local), ignored for remote SSE |
| **Rate limiting** | 60 requests/minute per token (sliding window) |
| **Memory limits** | Auth codes (500), registered clients (200), refresh tokens (1000) capped to prevent DoS |
| **SOQL injection protection** | User input escaped before inclusion in queries |
| **Read-only enforcement** | `sf_query` only accepts SELECT statements |
| **SF protected fields** | `OwnerId`, `IsConverted`, `IsDeleted`, `MasterRecordId` cannot be updated |
| **Pardot protected fields** | `email`, `score`, `grade`, `isDoNotEmail`, `isDoNotCall`, `salesforceId`, `crmContactFid`, `crmLeadFid` cannot be updated |
| **Audit logging** | SHA-256 key fingerprint logged per request |
| **Token encryption** | Per-user OAuth tokens encrypted at rest with Fernet (AES-128-CBC) |
| **Instance URL validation** | Only `*.salesforce.com` and `*.force.com` domains accepted |
| **Input sanitization** | Client names sanitized (control chars stripped, length limited) |

## Prerequisites

- **Python 3.10+** (uses `str | None` union syntax)
- **Salesforce Connected App** with OAuth enabled

### Creating a Connected App

1. In Salesforce: **Setup → App Manager → New Connected App**
2. Enable OAuth Settings
3. Set the callback URL to `https://your-server.up.railway.app/oauth/callback`
4. Add OAuth scopes: `api`, `refresh_token`, `pardot_api`
5. Save and note the **Consumer Key** and **Consumer Secret**

## Setup

### Local Development

```bash
git clone https://github.com/DaniilMai/salesforce-pardot-mcp.git
cd salesforce-pardot-mcp

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env with your Connected App credentials

python server.py
# → Listening on http://0.0.0.0:8000 (SSE)
# → Health check: http://localhost:8000/health
# → Login page: http://localhost:8000/login
```

### Railway Deployment

1. Push the repo to GitHub (or connect Railway to the repo directly)
2. Create a new Railway service from the repo
3. Set environment variables (see table below) as Railway service variables
4. Set health check path to `/health`
5. Deploy

The included `railway.toml` and `Dockerfile` handle the rest.

```bash
# Or build and run manually:
docker build -t sf-mcp .
docker run -p 8000:8000 --env-file .env sf-mcp
```

## Connecting an MCP Client

### Claude Desktop (MCP Native OAuth)

1. Open Claude Desktop: **Settings → Connectors → Add custom connector**
2. Enter URL: `https://your-server.up.railway.app/sse`
3. Leave OAuth Client ID/Secret empty (Dynamic Client Registration handles it)
4. Click Add → Salesforce login popup → Done

### Other MCP Clients (Manual Token)

After visiting `/login` and authenticating with Salesforce, paste the session token into your MCP client config:

```json
{
  "mcpServers": {
    "salesforce": {
      "url": "https://your-server.up.railway.app/sse",
      "headers": {
        "Authorization": "Bearer YOUR_SESSION_TOKEN"
      }
    }
  }
}
```

Restart the MCP client after saving.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SF_OAUTH_CLIENT_ID` | Yes | Connected App consumer key |
| `SF_OAUTH_CLIENT_SECRET` | Yes | Connected App consumer secret |
| `SF_OAUTH_REDIRECT_URI` | Yes | OAuth callback URL (e.g. `https://your-server/oauth/callback`) |
| `SF_OAUTH_LOGIN_URL` | No | Salesforce login URL (default: `https://login.salesforce.com`) |
| `ENCRYPTION_KEY` | Yes | Fernet key for token encryption (see below) |
| `PORT` | No | Server port (default: `8000`) |
| `ENABLE_WRITE_TOOLS` | No | Set to `true` to enable write tools (default: disabled, read-only mode) |
| `SESSION_TTL_SECONDS` | No | Session token lifetime in seconds (default: `86400` — 24 hours) |
| `TEAM_API_KEYS` | No | Comma-separated legacy API keys for backward compatibility |

Generate an encryption key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

See `.env.example` for a full template with comments.

## Running Tests

```bash
# Unit tests (no Salesforce connection needed)
python -m pytest tests/test_security.py -v

# OAuth flow tests
python -m pytest tests/test_oauth.py -v

# MCP OAuth tests (PKCE, token exchange, security hardening)
python -m pytest tests/test_mcp_oauth.py -v

# Integration tests (starts server subprocess)
python -m pytest tests/test_integration.py -v

# All tests via Docker
docker build -f Dockerfile.test -t sf-pardot-mcp-tests .
docker run --rm sf-pardot-mcp-tests
```

## Project Structure

```
server.py              # Entry point — FastMCP + SSE + health + OAuth routes
auth.py                # Bearer token middleware (session tokens + legacy keys)
user_context.py        # ContextVar for per-request user identity
token_store.py         # Fernet-encrypted per-user OAuth token storage
oauth.py               # Self-service OAuth flow (/login, /callback, /status, /revoke)
mcp_oauth.py           # MCP-native OAuth (metadata, authorize, token, register, PKCE)
tools/
  __init__.py          # Re-exports ALL_TOOLS list (16 read + 5 write, write opt-in)
  salesforce.py        # 10 Salesforce tools (SOQL, CRUD, pipeline, activities)
  pardot.py            # 11 Pardot tools (prospects, campaigns, activities, emails)
tests/
  test_security.py     # Unit tests — SOQL injection, field protection, auth, rate limiting
  test_oauth.py        # OAuth flow tests — login redirect, callback, status, revoke
  test_mcp_oauth.py    # MCP OAuth tests — PKCE, token exchange, security hardening
  test_integration.py  # Integration tests — server startup, health, SSE
Dockerfile             # Production container
Dockerfile.test        # Test runner container
railway.toml           # Railway deployment config
requirements.txt       # Python dependencies
.env.example           # Environment variable template
```

## License

MIT — see [LICENSE](LICENSE) for details.
