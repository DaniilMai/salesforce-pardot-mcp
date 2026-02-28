# Salesforce + Pardot MCP Server

A remote [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server providing Salesforce CRM and Pardot (Marketing Cloud Account Engagement) tools over SSE transport. Built with [FastMCP](https://github.com/jlowin/fastmcp), designed for deployment on [Railway](https://railway.app/).

Users connect their own Salesforce org via a browser-based OAuth flow — no admin-generated API keys required.

## How It Works

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

## Available Tools (21)

### Salesforce Tools (`sf_*`)

| Tool | Description |
|---|---|
| `sf_query` | Run arbitrary SOQL SELECT queries (read-only enforced) |
| `sf_get_leads` | Get leads with filters (status, creation recency, lead source) |
| `sf_get_contacts` | Get contacts with filters (name, email, account ID) |
| `sf_update_lead` | Update lead fields (protected fields blocked) |
| `sf_update_contact` | Update contact fields (protected fields blocked) |
| `sf_create_lead` | Create a new lead (LastName + Company required) |
| `sf_pipeline_report` | Open opportunities aggregated by stage |
| `sf_get_tasks` | Get tasks with filters (who/what ID, status, date range, subject) |
| `sf_get_events` | Get events with filters (who/what ID, datetime range) |
| `sf_get_activity_history` | Combined tasks + events for a record, sorted by date |

### Pardot Tools (`pardot_*`)

| Tool | Description |
|---|---|
| `pardot_get_prospects` | Get prospects with filters (email, score, campaign) |
| `pardot_get_prospect_by_email` | Look up a single prospect by email address |
| `pardot_update_prospect` | Update prospect fields |
| `pardot_get_campaigns` | List all campaigns |
| `pardot_get_lists` | List all lists |
| `pardot_get_forms` | List all forms |
| `pardot_add_prospect_to_list` | Add a prospect to a list |
| `pardot_get_visitor_activities` | Get visitor activities (page views, form fills, email clicks) |
| `pardot_get_form_handlers` | List all form handlers |
| `pardot_get_emails` | List email templates and sends |
| `pardot_get_lifecycle_history` | Get lifecycle stage progression for a prospect |

## Security

| Feature | Details |
|---|---|
| **Authentication** | Bearer token — session tokens (from OAuth) or legacy API keys |
| **Rate limiting** | 60 requests/minute per token (sliding window) |
| **SOQL injection protection** | User input escaped before inclusion in queries |
| **Read-only enforcement** | `sf_query` only accepts SELECT statements |
| **Protected fields** | `OwnerId`, `IsConverted`, `IsDeleted`, `MasterRecordId` cannot be updated |
| **Audit logging** | SHA-256 key fingerprint logged per request |
| **Token encryption** | Per-user OAuth tokens encrypted at rest with Fernet (AES-128-CBC) |
| **Instance URL validation** | Only `*.salesforce.com` and `*.force.com` domains accepted |

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
tools/
  __init__.py          # Re-exports ALL_TOOLS list (21 tools)
  salesforce.py        # 10 Salesforce tools (SOQL, CRUD, pipeline, activities)
  pardot.py            # 11 Pardot tools (prospects, campaigns, activities, emails)
tests/
  test_security.py     # Unit tests — SOQL injection, field protection, auth, rate limiting
  test_oauth.py        # OAuth flow tests — login redirect, callback, status, revoke
  test_integration.py  # Integration tests — server startup, health, SSE
Dockerfile             # Production container
Dockerfile.test        # Test runner container
railway.toml           # Railway deployment config
requirements.txt       # Python dependencies
.env.example           # Environment variable template
```

## License

MIT — see [LICENSE](LICENSE) for details.
