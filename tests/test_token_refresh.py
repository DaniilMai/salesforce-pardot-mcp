"""
Tests for proactive SF token refresh lifecycle.

Validates ensure_fresh_sf_token() triggers refresh when token is near
expiry, and that Pardot 401-retry calls ensure_fresh_sf_token() to get
a genuinely new token.
"""

import os
import time
import unittest
from unittest.mock import patch, MagicMock

os.environ.setdefault("TEAM_API_KEYS", "test-key-1")
os.environ.setdefault("ENCRYPTION_KEY", "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXQ9PQ==")


class TestEnsureFreshSFToken(unittest.TestCase):
    """Verify proactive SF token refresh."""

    @patch("tools.salesforce.get_token_store")
    @patch("tools.salesforce._refresh_oauth_token")
    def test_fresh_token_not_refreshed(self, mock_refresh, mock_store):
        """Token younger than threshold should NOT trigger refresh."""
        from tools.salesforce import ensure_fresh_sf_token

        store_instance = MagicMock()
        store_instance.get.return_value = {
            "access_token": "at",
            "refresh_token": "rt",
            "instance_url": "https://test.my.salesforce.com",
            "issued_at": time.time() - 3600,  # 1 hour old (< 1h55m threshold)
            "pardot_business_unit_id": None,
        }
        mock_store.return_value = store_instance

        ensure_fresh_sf_token("test-key")

        mock_refresh.assert_not_called()

    @patch("tools.salesforce._sf_clients", {})
    @patch("tools.salesforce.get_token_store")
    @patch("tools.salesforce._refresh_oauth_token")
    def test_near_expiry_token_refreshed(self, mock_refresh, mock_store):
        """Token older than (2h - 5min) should trigger refresh."""
        from tools.salesforce import ensure_fresh_sf_token

        store_instance = MagicMock()
        old_tokens = {
            "access_token": "old-at",
            "refresh_token": "rt",
            "instance_url": "https://test.my.salesforce.com",
            "issued_at": time.time() - 7000,  # ~1h56m old (> 1h55m threshold)
            "pardot_business_unit_id": None,
        }
        store_instance.get.return_value = old_tokens
        mock_store.return_value = store_instance

        new_tokens = {
            "access_token": "new-at",
            "refresh_token": "rt",
            "instance_url": "https://test.my.salesforce.com",
            "issued_at": time.time(),
            "pardot_business_unit_id": None,
        }
        mock_refresh.return_value = new_tokens

        ensure_fresh_sf_token("test-key")

        mock_refresh.assert_called_once_with(old_tokens)
        store_instance.put.assert_called_once_with("test-key", new_tokens)

    @patch("tools.salesforce.get_token_store")
    @patch("tools.salesforce._refresh_oauth_token")
    def test_no_refresh_token_skips(self, mock_refresh, mock_store):
        """Token without refresh_token should NOT attempt refresh."""
        from tools.salesforce import ensure_fresh_sf_token

        store_instance = MagicMock()
        store_instance.get.return_value = {
            "access_token": "at",
            "refresh_token": "",  # No refresh token
            "instance_url": "https://test.my.salesforce.com",
            "issued_at": time.time() - 7200,  # Expired but no refresh_token
            "pardot_business_unit_id": None,
        }
        mock_store.return_value = store_instance

        ensure_fresh_sf_token("test-key")

        mock_refresh.assert_not_called()

    @patch("tools.salesforce.get_token_store")
    def test_no_api_key_skips(self, mock_store):
        """None api_key should skip refresh."""
        from tools.salesforce import ensure_fresh_sf_token
        ensure_fresh_sf_token(None)
        mock_store.assert_not_called()

    @patch("tools.salesforce.get_token_store")
    @patch("tools.salesforce._refresh_oauth_token")
    def test_failed_refresh_doesnt_crash(self, mock_refresh, mock_store):
        """If refresh fails (returns None), should log warning but not crash."""
        from tools.salesforce import ensure_fresh_sf_token

        store_instance = MagicMock()
        store_instance.get.return_value = {
            "access_token": "old-at",
            "refresh_token": "rt",
            "instance_url": "https://test.my.salesforce.com",
            "issued_at": time.time() - 7200,
            "pardot_business_unit_id": None,
        }
        mock_store.return_value = store_instance
        mock_refresh.return_value = None  # Refresh failed

        # Should not raise
        ensure_fresh_sf_token("test-key")

        mock_refresh.assert_called_once()
        store_instance.put.assert_not_called()


class TestGetSFClientRefresh(unittest.TestCase):
    """Verify get_sf_client() calls ensure_fresh_sf_token()."""

    @patch("tools.salesforce.ensure_fresh_sf_token")
    @patch("tools.salesforce._get_oauth_sf_client")
    @patch("tools.salesforce.get_current_api_key", return_value="test-api-key")
    def test_get_sf_client_calls_refresh(self, mock_key, mock_get_client, mock_ensure):
        from tools.salesforce import get_sf_client
        mock_get_client.return_value = MagicMock()

        get_sf_client()

        mock_ensure.assert_called_once_with("test-api-key")


class TestPardotRefreshCallsEnsure(unittest.TestCase):
    """Verify Pardot _refresh_token() calls ensure_fresh_sf_token()."""

    @patch("tools.pardot.get_token_store")
    @patch("tools.salesforce.ensure_fresh_sf_token")
    def test_pardot_refresh_calls_ensure_fresh(self, mock_ensure, mock_store):
        from tools.pardot import PardotClient

        store_instance = MagicMock()
        store_instance.get.return_value = {
            "access_token": "fresh-at",
            "refresh_token": "rt",
            "instance_url": "https://test.my.salesforce.com",
            "issued_at": time.time(),
            "pardot_business_unit_id": None,
        }
        mock_store.return_value = store_instance

        client = PardotClient(api_key="test-key")
        token = client._refresh_token()

        mock_ensure.assert_called_once_with("test-key")
        self.assertEqual(token, "fresh-at")


if __name__ == "__main__":
    unittest.main()
