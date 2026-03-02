"""
Tests for MCP-native OAuth 2.0 flow.

Validates well-known endpoints, PKCE verification, authorization code flow,
token exchange, token refresh, dynamic client registration, and security
hardening (redirect_uri validation, memory limits, timing-safe comparison).
"""

import asyncio
import hashlib
import base64
import os
import time
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

# Set up env vars before importing modules
os.environ.setdefault("TEAM_API_KEYS", "test-key-1,test-key-2")
os.environ.setdefault("SF_OAUTH_CLIENT_ID", "test-client-id")
os.environ.setdefault("SF_OAUTH_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("SF_OAUTH_REDIRECT_URI", "http://localhost:8000/oauth/callback")
os.environ.setdefault("SF_OAUTH_LOGIN_URL", "https://login.salesforce.com")
os.environ.setdefault("ENCRYPTION_KEY", "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXQ9PQ==")


def _make_request(headers=None, query_params=None, scheme="https", host="test-server.up.railway.app"):
    """Create a mock Starlette request."""
    request = MagicMock()
    request.headers = headers or {}
    request.headers.setdefault("host", host)
    request.query_params = query_params or {}
    request.url = MagicMock()
    request.url.scheme = scheme
    return request


def _generate_pkce():
    """Generate a valid PKCE code_verifier and code_challenge pair."""
    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


class TestPKCE(unittest.TestCase):
    """Verify PKCE S256 implementation."""

    def test_valid_pkce(self):
        from mcp_oauth import verify_pkce
        verifier, challenge = _generate_pkce()
        self.assertTrue(verify_pkce(verifier, challenge))

    def test_invalid_pkce(self):
        from mcp_oauth import verify_pkce
        _, challenge = _generate_pkce()
        self.assertFalse(verify_pkce("wrong-verifier", challenge))

    def test_rfc7636_example(self):
        """Test with the RFC 7636 appendix B example."""
        from mcp_oauth import verify_pkce
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        self.assertTrue(verify_pkce(verifier, expected_challenge))


class TestProtectedResourceMetadata(unittest.TestCase):
    """Verify /.well-known/oauth-protected-resource endpoint."""

    def test_returns_resource_metadata(self):
        from mcp_oauth import protected_resource_metadata
        request = _make_request()
        result = asyncio.get_event_loop().run_until_complete(protected_resource_metadata(request))
        self.assertEqual(result.status_code, 200)
        import json
        body = json.loads(result.body)
        self.assertIn("resource", body)
        self.assertIn("authorization_servers", body)
        self.assertIn("bearer_methods_supported", body)
        self.assertEqual(body["bearer_methods_supported"], ["header"])
        self.assertEqual(len(body["authorization_servers"]), 1)

    def test_server_url_ignores_spoofed_headers(self):
        """Server URL must come from SF_OAUTH_REDIRECT_URI, not request headers."""
        from mcp_oauth import protected_resource_metadata
        request = _make_request(headers={
            "x-forwarded-proto": "https",
            "x-forwarded-host": "evil.example.com",
            "host": "localhost:8000",
        })
        result = asyncio.get_event_loop().run_until_complete(protected_resource_metadata(request))
        import json
        body = json.loads(result.body)
        # Must use the env-configured redirect URI origin, NOT the spoofed header
        self.assertEqual(body["resource"], "http://localhost:8000")
        self.assertNotIn("evil.example.com", body["resource"])


class TestAuthorizationServerMetadata(unittest.TestCase):
    """Verify /.well-known/oauth-authorization-server endpoint."""

    def test_returns_server_metadata(self):
        from mcp_oauth import authorization_server_metadata
        request = _make_request()
        result = asyncio.get_event_loop().run_until_complete(authorization_server_metadata(request))
        self.assertEqual(result.status_code, 200)
        import json
        body = json.loads(result.body)
        self.assertIn("issuer", body)
        self.assertIn("authorization_endpoint", body)
        self.assertIn("token_endpoint", body)
        self.assertIn("registration_endpoint", body)
        self.assertEqual(body["code_challenge_methods_supported"], ["S256"])
        self.assertIn("authorization_code", body["grant_types_supported"])
        self.assertIn("refresh_token", body["grant_types_supported"])
        self.assertEqual(body["response_types_supported"], ["code"])


class TestOAuthAuthorize(unittest.TestCase):
    """Verify /oauth/authorize endpoint."""

    def test_missing_params_returns_400(self):
        from mcp_oauth import oauth_authorize
        request = _make_request(query_params={})
        result = asyncio.get_event_loop().run_until_complete(oauth_authorize(request))
        self.assertEqual(result.status_code, 400)

    def test_unsupported_challenge_method_returns_400(self):
        from mcp_oauth import oauth_authorize
        request = _make_request(query_params={
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
            "code_challenge": "abc123",
            "code_challenge_method": "plain",
        })
        result = asyncio.get_event_loop().run_until_complete(oauth_authorize(request))
        self.assertEqual(result.status_code, 400)
        import json
        body = json.loads(result.body)
        self.assertIn("S256", body["error_description"])

    def test_valid_params_redirects_to_salesforce(self):
        from mcp_oauth import oauth_authorize
        _, challenge = _generate_pkce()
        request = _make_request(query_params={
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "test-state-123",
        })
        result = asyncio.get_event_loop().run_until_complete(oauth_authorize(request))
        # Should redirect to Salesforce
        self.assertEqual(result.status_code, 307)
        location = dict(result.headers).get("location", "")
        self.assertIn("login.salesforce.com", location)
        self.assertIn("response_type=code", location)


class TestOAuthToken(unittest.TestCase):
    """Verify /oauth/token endpoint."""

    def test_unsupported_grant_type(self):
        from mcp_oauth import oauth_token
        request = MagicMock()
        form_data = {"grant_type": "client_credentials"}
        request.form = AsyncMock(return_value=form_data)
        result = asyncio.get_event_loop().run_until_complete(oauth_token(request))
        self.assertEqual(result.status_code, 400)
        import json
        body = json.loads(result.body)
        self.assertEqual(body["error"], "unsupported_grant_type")

    def test_missing_code_returns_400(self):
        from mcp_oauth import oauth_token
        request = MagicMock()
        form_data = {"grant_type": "authorization_code"}
        request.form = AsyncMock(return_value=form_data)
        result = asyncio.get_event_loop().run_until_complete(oauth_token(request))
        self.assertEqual(result.status_code, 400)

    def test_invalid_code_returns_400(self):
        from mcp_oauth import oauth_token
        request = MagicMock()
        form_data = {
            "grant_type": "authorization_code",
            "code": "nonexistent-code",
            "code_verifier": "some-verifier",
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
        }
        request.form = AsyncMock(return_value=form_data)
        result = asyncio.get_event_loop().run_until_complete(oauth_token(request))
        self.assertEqual(result.status_code, 400)
        import json
        body = json.loads(result.body)
        self.assertEqual(body["error"], "invalid_grant")

    @patch("mcp_oauth.get_token_store")
    def test_valid_code_exchange(self, mock_store):
        from mcp_oauth import oauth_token, _state_store

        verifier, challenge = _generate_pkce()
        ss = _state_store()

        # Plant a valid authorization code
        auth_code = "test-auth-code-123"
        ss.put_auth_code(auth_code, {
            "type": "code",
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
            "code_challenge": challenge,
            "sf_access_token": "sf-access-token",
            "sf_refresh_token": "sf-refresh-token",
            "sf_instance_url": "https://myorg.my.salesforce.com",
            "created_at": time.time(),
        })

        store_instance = MagicMock()
        mock_store.return_value = store_instance

        request = MagicMock()
        form_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "code_verifier": verifier,
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
        }
        request.form = AsyncMock(return_value=form_data)

        result = asyncio.get_event_loop().run_until_complete(oauth_token(request))
        self.assertEqual(result.status_code, 200)

        import json
        body = json.loads(result.body)
        self.assertIn("access_token", body)
        self.assertIn("refresh_token", body)
        self.assertEqual(body["token_type"], "Bearer")
        self.assertIn("expires_in", body)
        self.assertGreater(len(body["access_token"]), 40)
        self.assertGreater(len(body["refresh_token"]), 40)

        # Token store should have been called
        store_instance.put.assert_called_once()

        # Auth code should be consumed (single-use)
        self.assertIsNone(ss.get_auth_code(auth_code))

    @patch("mcp_oauth.get_token_store")
    def test_wrong_pkce_rejected(self, mock_store):
        from mcp_oauth import oauth_token, _state_store

        _, challenge = _generate_pkce()

        auth_code = "test-auth-code-wrong-pkce"
        _state_store().put_auth_code(auth_code, {
            "type": "code",
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
            "code_challenge": challenge,
            "sf_access_token": "sf-access-token",
            "sf_refresh_token": "sf-refresh-token",
            "sf_instance_url": "https://myorg.my.salesforce.com",
            "created_at": time.time(),
        })

        store_instance = MagicMock()
        mock_store.return_value = store_instance

        request = MagicMock()
        form_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "code_verifier": "totally-wrong-verifier",
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
        }
        request.form = AsyncMock(return_value=form_data)

        result = asyncio.get_event_loop().run_until_complete(oauth_token(request))
        self.assertEqual(result.status_code, 400)

        import json
        body = json.loads(result.body)
        self.assertEqual(body["error"], "invalid_grant")
        self.assertIn("PKCE", body["error_description"])

        # Token store should NOT have been called
        store_instance.put.assert_not_called()

    def test_client_id_mismatch_rejected(self):
        from mcp_oauth import oauth_token, _state_store

        verifier, challenge = _generate_pkce()

        auth_code = "test-auth-code-client-mismatch"
        _state_store().put_auth_code(auth_code, {
            "type": "code",
            "client_id": "original-client",
            "redirect_uri": "http://localhost/callback",
            "code_challenge": challenge,
            "sf_access_token": "sf-access-token",
            "sf_refresh_token": "sf-refresh-token",
            "sf_instance_url": "https://myorg.my.salesforce.com",
            "created_at": time.time(),
        })

        request = MagicMock()
        form_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "code_verifier": verifier,
            "client_id": "different-client",
            "redirect_uri": "http://localhost/callback",
        }
        request.form = AsyncMock(return_value=form_data)

        result = asyncio.get_event_loop().run_until_complete(oauth_token(request))
        self.assertEqual(result.status_code, 400)
        import json
        body = json.loads(result.body)
        self.assertIn("client_id", body["error_description"])

    def test_expired_code_rejected(self):
        from mcp_oauth import oauth_token, _state_store

        verifier, challenge = _generate_pkce()

        auth_code = "test-expired-code"
        _state_store().put_auth_code(auth_code, {
            "type": "code",
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
            "code_challenge": challenge,
            "sf_access_token": "sf-access-token",
            "sf_refresh_token": "sf-refresh-token",
            "sf_instance_url": "https://myorg.my.salesforce.com",
            "created_at": time.time() - 700,  # Expired (>600s)
        })

        request = MagicMock()
        form_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "code_verifier": verifier,
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
        }
        request.form = AsyncMock(return_value=form_data)

        result = asyncio.get_event_loop().run_until_complete(oauth_token(request))
        self.assertEqual(result.status_code, 400)
        import json
        body = json.loads(result.body)
        self.assertEqual(body["error"], "invalid_grant")


class TestOAuthRefreshToken(unittest.TestCase):
    """Verify refresh token flow."""

    def test_missing_refresh_token_returns_400(self):
        from mcp_oauth import oauth_token
        request = MagicMock()
        form_data = {"grant_type": "refresh_token"}
        request.form = AsyncMock(return_value=form_data)
        result = asyncio.get_event_loop().run_until_complete(oauth_token(request))
        self.assertEqual(result.status_code, 400)

    def test_invalid_refresh_token_returns_400(self):
        from mcp_oauth import oauth_token
        request = MagicMock()
        form_data = {"grant_type": "refresh_token", "refresh_token": "invalid-token"}
        request.form = AsyncMock(return_value=form_data)
        result = asyncio.get_event_loop().run_until_complete(oauth_token(request))
        self.assertEqual(result.status_code, 400)
        import json
        body = json.loads(result.body)
        self.assertEqual(body["error"], "invalid_grant")

    @patch("mcp_oauth.httpx.AsyncClient")
    @patch("mcp_oauth.get_token_store")
    def test_valid_refresh_returns_new_tokens(self, mock_store, mock_client_cls):
        from mcp_oauth import oauth_token, _state_store

        ss = _state_store()

        # Set up refresh token mapping
        refresh_tok = "test-refresh-tok-valid"
        old_session = "old-session-token"
        ss.put_refresh_token(refresh_tok, {
            "session_token": old_session,
            "created_at": time.time(),
        }, ttl=86400)

        # Mock token store with existing tokens
        store_instance = MagicMock()
        store_instance.get.return_value = {
            "access_token": "sf-access-old",
            "refresh_token": "sf-refresh-old",
            "instance_url": "https://myorg.my.salesforce.com",
            "issued_at": time.time() - 3600,
            "pardot_business_unit_id": None,
        }
        mock_store.return_value = store_instance

        # Mock SF refresh response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "sf-access-new",
            "instance_url": "https://myorg.my.salesforce.com",
        }
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_http

        request = MagicMock()
        form_data = {"grant_type": "refresh_token", "refresh_token": refresh_tok}
        request.form = AsyncMock(return_value=form_data)

        result = asyncio.get_event_loop().run_until_complete(oauth_token(request))
        self.assertEqual(result.status_code, 200)

        import json
        body = json.loads(result.body)
        self.assertIn("access_token", body)
        self.assertIn("refresh_token", body)
        self.assertEqual(body["token_type"], "Bearer")
        # New tokens should differ from old
        self.assertNotEqual(body["access_token"], old_session)
        self.assertNotEqual(body["refresh_token"], refresh_tok)

        # Old refresh token should be consumed (pop returns None)
        self.assertIsNone(ss.pop_refresh_token(refresh_tok))

        # Old session should be deleted
        store_instance.delete.assert_called_once_with(old_session)


class TestDynamicClientRegistration(unittest.TestCase):
    """Verify /oauth/register endpoint."""

    def test_missing_redirect_uris_returns_400(self):
        from mcp_oauth import oauth_register
        request = MagicMock()
        request.json = AsyncMock(return_value={"client_name": "test"})
        result = asyncio.get_event_loop().run_until_complete(oauth_register(request))
        self.assertEqual(result.status_code, 400)

    def test_valid_registration_returns_client_id(self):
        from mcp_oauth import oauth_register
        request = MagicMock()
        request.json = AsyncMock(return_value={
            "client_name": "Claude Desktop",
            "redirect_uris": ["http://localhost/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        })
        result = asyncio.get_event_loop().run_until_complete(oauth_register(request))
        self.assertEqual(result.status_code, 201)

        import json
        body = json.loads(result.body)
        self.assertIn("client_id", body)
        self.assertEqual(body["client_name"], "Claude Desktop")
        self.assertEqual(body["redirect_uris"], ["http://localhost/callback"])
        self.assertGreater(len(body["client_id"]), 20)

    def test_invalid_json_returns_400(self):
        from mcp_oauth import oauth_register
        request = MagicMock()
        request.json = AsyncMock(side_effect=Exception("invalid JSON"))
        result = asyncio.get_event_loop().run_until_complete(oauth_register(request))
        self.assertEqual(result.status_code, 400)


class TestMCPOAuthCallback(unittest.TestCase):
    """Verify MCP-aware /oauth/callback handler."""

    def test_non_mcp_flow_returns_none(self):
        from mcp_oauth import mcp_oauth_callback
        request = _make_request(query_params={"code": "test", "state": "unknown-state"})
        result = asyncio.get_event_loop().run_until_complete(mcp_oauth_callback(request))
        self.assertIsNone(result)

    def test_missing_params_returns_none(self):
        from mcp_oauth import mcp_oauth_callback
        request = _make_request(query_params={})
        result = asyncio.get_event_loop().run_until_complete(mcp_oauth_callback(request))
        self.assertIsNone(result)

    @patch("mcp_oauth.httpx.AsyncClient")
    def test_mcp_callback_redirects_to_claude(self, mock_client_cls):
        from mcp_oauth import mcp_oauth_callback, _state_store

        ss = _state_store()

        # Plant a pending MCP authorization
        internal_state = "mcp-internal-state"
        ss.put_auth_code(internal_state, {
            "type": "pending",
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
            "state": "claude-state",
            "code_challenge": "test-challenge",
            "scope": "read",
            "created_at": time.time(),
        })

        # Mock SF token exchange
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "sf-access-token",
            "refresh_token": "sf-refresh-token",
            "instance_url": "https://myorg.my.salesforce.com",
        }
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_http

        request = _make_request(query_params={"code": "sf-auth-code", "state": internal_state})

        result = asyncio.get_event_loop().run_until_complete(mcp_oauth_callback(request))
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 307)

        location = dict(result.headers).get("location", "")
        self.assertIn("localhost/callback", location)
        self.assertIn("code=", location)
        self.assertIn("state=claude-state", location)


class TestAuthCodeSingleUse(unittest.TestCase):
    """Verify authorization codes are single-use."""

    @patch("mcp_oauth.get_token_store")
    def test_code_cannot_be_reused(self, mock_store):
        from mcp_oauth import oauth_token, _state_store

        verifier, challenge = _generate_pkce()
        ss = _state_store()

        auth_code = "single-use-code"
        ss.put_auth_code(auth_code, {
            "type": "code",
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
            "code_challenge": challenge,
            "sf_access_token": "sf-access",
            "sf_refresh_token": "sf-refresh",
            "sf_instance_url": "https://myorg.my.salesforce.com",
            "created_at": time.time(),
        })

        store_instance = MagicMock()
        mock_store.return_value = store_instance

        request = MagicMock()
        form_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "code_verifier": verifier,
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
        }
        request.form = AsyncMock(return_value=form_data)

        # First exchange — should succeed
        result = asyncio.get_event_loop().run_until_complete(oauth_token(request))
        self.assertEqual(result.status_code, 200)

        # Second exchange with same code — should fail
        request.form = AsyncMock(return_value=form_data)
        result2 = asyncio.get_event_loop().run_until_complete(oauth_token(request))
        self.assertEqual(result2.status_code, 400)
        import json
        body = json.loads(result2.body)
        self.assertEqual(body["error"], "invalid_grant")


# ===================================================================
# Security tests for hardening fixes
# ===================================================================


class TestRedirectUriValidation(unittest.TestCase):
    """Verify redirect_uri validation prevents open redirect attacks (FIX #1, #6)."""

    def test_https_accepted(self):
        from mcp_oauth import _validate_redirect_uri
        self.assertTrue(_validate_redirect_uri("https://example.com/callback"))

    def test_http_localhost_accepted(self):
        from mcp_oauth import _validate_redirect_uri
        self.assertTrue(_validate_redirect_uri("http://localhost/callback"))
        self.assertTrue(_validate_redirect_uri("http://localhost:3000/callback"))
        self.assertTrue(_validate_redirect_uri("http://127.0.0.1/callback"))

    def test_http_remote_rejected(self):
        """http:// to non-localhost must be rejected."""
        from mcp_oauth import _validate_redirect_uri
        self.assertFalse(_validate_redirect_uri("http://evil.com/callback"))
        self.assertFalse(_validate_redirect_uri("http://attacker.example.com/steal"))

    def test_javascript_scheme_rejected(self):
        from mcp_oauth import _validate_redirect_uri
        self.assertFalse(_validate_redirect_uri("javascript:alert(1)"))

    def test_data_scheme_rejected(self):
        from mcp_oauth import _validate_redirect_uri
        self.assertFalse(_validate_redirect_uri("data:text/html,<script>alert(1)</script>"))

    def test_empty_rejected(self):
        from mcp_oauth import _validate_redirect_uri
        self.assertFalse(_validate_redirect_uri(""))

    def test_no_hostname_rejected(self):
        from mcp_oauth import _validate_redirect_uri
        self.assertFalse(_validate_redirect_uri("https://"))

    def test_ftp_rejected(self):
        from mcp_oauth import _validate_redirect_uri
        self.assertFalse(_validate_redirect_uri("ftp://example.com/callback"))

    def test_authorize_rejects_javascript_redirect(self):
        """The authorize endpoint must reject javascript: redirect_uri."""
        from mcp_oauth import oauth_authorize
        _, challenge = _generate_pkce()
        request = _make_request(query_params={
            "client_id": "test",
            "redirect_uri": "javascript:alert(document.cookie)",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        result = asyncio.get_event_loop().run_until_complete(oauth_authorize(request))
        self.assertEqual(result.status_code, 400)
        import json
        body = json.loads(result.body)
        self.assertIn("redirect_uri", body["error_description"])

    def test_authorize_rejects_http_remote_redirect(self):
        """The authorize endpoint must reject http:// to non-localhost."""
        from mcp_oauth import oauth_authorize
        _, challenge = _generate_pkce()
        request = _make_request(query_params={
            "client_id": "test",
            "redirect_uri": "http://evil.com/steal-code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        result = asyncio.get_event_loop().run_until_complete(oauth_authorize(request))
        self.assertEqual(result.status_code, 400)


class TestDCRRedirectUriValidation(unittest.TestCase):
    """Verify DCR redirect_uri enforcement (FIX #1)."""

    def test_registered_client_must_match_uris(self):
        """If client is DCR-registered, redirect_uri must match registered URIs."""
        from mcp_oauth import _validate_redirect_uri_for_client, _state_store

        ss = _state_store()
        client_id = "test-dcr-client-validate"
        ss.put_client(client_id, {
            "redirect_uris": ["https://app.example.com/callback"],
            "created_at": time.time(),
        })

        # Matching URI — accepted
        self.assertTrue(_validate_redirect_uri_for_client(client_id, "https://app.example.com/callback"))
        # Non-matching URI — rejected even if scheme is valid
        self.assertFalse(_validate_redirect_uri_for_client(client_id, "https://evil.com/callback"))

    def test_unregistered_client_validated_by_scheme(self):
        """Unregistered clients have their redirect_uri validated by scheme."""
        from mcp_oauth import _validate_redirect_uri_for_client
        self.assertTrue(_validate_redirect_uri_for_client("unknown-client", "https://example.com/cb"))
        self.assertFalse(_validate_redirect_uri_for_client("unknown-client", "javascript:alert(1)"))

    def test_register_rejects_invalid_redirect_uris(self):
        """DCR registration must reject invalid redirect_uris."""
        from mcp_oauth import oauth_register
        request = MagicMock()
        request.json = AsyncMock(return_value={
            "client_name": "Evil Client",
            "redirect_uris": ["javascript:alert(1)"],
        })
        result = asyncio.get_event_loop().run_until_complete(oauth_register(request))
        self.assertEqual(result.status_code, 400)
        import json
        body = json.loads(result.body)
        self.assertIn("redirect_uri", body["error_description"].lower())

    def test_register_rejects_non_list_redirect_uris(self):
        """redirect_uris must be a list."""
        from mcp_oauth import oauth_register
        request = MagicMock()
        request.json = AsyncMock(return_value={
            "client_name": "Bad Client",
            "redirect_uris": "http://localhost/callback",  # string, not list
        })
        result = asyncio.get_event_loop().run_until_complete(oauth_register(request))
        self.assertEqual(result.status_code, 400)


class TestMemoryLimits(unittest.TestCase):
    """Verify in-memory stores have size limits (FIX #2, #3, #4)."""

    def test_max_pending_codes_enforced(self):
        """Exceeding MAX_PENDING_CODES returns 429."""
        from mcp_oauth import oauth_authorize, _state_store, MAX_PENDING_CODES

        _, challenge = _generate_pkce()
        ss = _state_store()

        # Fill up auth codes to the limit
        for i in range(MAX_PENDING_CODES):
            ss.put_auth_code(f"fake-code-{i}", {"created_at": time.time(), "type": "pending"})

        try:
            request = _make_request(query_params={
                "client_id": "test",
                "redirect_uri": "http://localhost/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            })
            result = asyncio.get_event_loop().run_until_complete(oauth_authorize(request))
            self.assertEqual(result.status_code, 429)
        finally:
            # Cleanup: pop all fake codes
            for i in range(MAX_PENDING_CODES):
                ss.pop_auth_code(f"fake-code-{i}")

    def test_max_registered_clients_enforced(self):
        """Exceeding MAX_REGISTERED_CLIENTS returns 429."""
        from mcp_oauth import oauth_register, _state_store, MAX_REGISTERED_CLIENTS

        ss = _state_store()
        for i in range(MAX_REGISTERED_CLIENTS):
            ss.put_client(f"fake-client-{i}", {"created_at": time.time()})

        try:
            request = MagicMock()
            request.json = AsyncMock(return_value={
                "client_name": "One Too Many",
                "redirect_uris": ["http://localhost/callback"],
            })
            result = asyncio.get_event_loop().run_until_complete(oauth_register(request))
            self.assertEqual(result.status_code, 429)
        finally:
            # InMemoryOAuthStateStore — access internal dict for cleanup
            if hasattr(ss, '_clients'):
                for i in range(MAX_REGISTERED_CLIENTS):
                    ss._clients.pop(f"fake-client-{i}", None)

    def test_refresh_token_single_use(self):
        """Refresh tokens are consumed on use (single-use)."""
        from mcp_oauth import _state_store

        ss = _state_store()
        ss.put_refresh_token("test-rt-single", {
            "session_token": "test-session",
            "created_at": time.time(),
        }, ttl=86400)

        # First pop — should succeed
        data = ss.pop_refresh_token("test-rt-single")
        self.assertIsNotNone(data)
        self.assertEqual(data["session_token"], "test-session")

        # Second pop — should return None (consumed)
        data2 = ss.pop_refresh_token("test-rt-single")
        self.assertIsNone(data2)


class TestClientNameSanitization(unittest.TestCase):
    """Verify client_name is sanitized (FIX #9)."""

    def test_control_chars_stripped(self):
        from mcp_oauth import _sanitize_client_name
        self.assertEqual(_sanitize_client_name("normal"), "normal")
        self.assertEqual(_sanitize_client_name("evil\x00name"), "evilname")
        self.assertEqual(_sanitize_client_name("log\ninjection"), "loginjection")

    def test_length_limited(self):
        from mcp_oauth import _sanitize_client_name
        long_name = "A" * 200
        self.assertEqual(len(_sanitize_client_name(long_name)), 100)

    def test_non_string_returns_unnamed(self):
        from mcp_oauth import _sanitize_client_name
        self.assertEqual(_sanitize_client_name(None), "unnamed")
        self.assertEqual(_sanitize_client_name(123), "unnamed")

    def test_empty_returns_unnamed(self):
        from mcp_oauth import _sanitize_client_name
        self.assertEqual(_sanitize_client_name(""), "unnamed")


class TestSFRedirectUriFromEnv(unittest.TestCase):
    """Verify SF redirect_uri uses env var, not request headers (FIX #5)."""

    def test_authorize_uses_env_redirect_uri(self):
        """The SF OAuth redirect must use SF_OAUTH_REDIRECT_URI env var."""
        from mcp_oauth import oauth_authorize

        _, challenge = _generate_pkce()
        # Use a spoofed X-Forwarded-Host — should NOT affect SF redirect
        request = _make_request(
            headers={
                "x-forwarded-host": "evil-spoofed-host.com",
                "host": "real-server.railway.app",
            },
            query_params={
                "client_id": "test",
                "redirect_uri": "http://localhost/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        result = asyncio.get_event_loop().run_until_complete(oauth_authorize(request))
        self.assertEqual(result.status_code, 307)

        location = dict(result.headers).get("location", "")
        # SF redirect_uri param should use env var, NOT the spoofed host
        self.assertNotIn("evil-spoofed-host", location)
        # Should contain the configured redirect URI from env
        self.assertIn("redirect_uri=", location)


if __name__ == "__main__":
    unittest.main()
