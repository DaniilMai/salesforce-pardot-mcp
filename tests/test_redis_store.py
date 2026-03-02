"""
Tests for redis_store.py — InMemoryOAuthStateStore behavior.

RedisTokenStore and RedisOAuthStateStore are tested indirectly when a real
Redis is available; these tests cover the InMemoryOAuthStateStore fallback
and the OAuthStateStoreBase interface contract.
"""

import time
import unittest


class TestInMemoryOAuthStateStore(unittest.TestCase):
    """Verify InMemoryOAuthStateStore implements the full interface."""

    def _make_store(self):
        from redis_store import InMemoryOAuthStateStore
        return InMemoryOAuthStateStore()

    # --- Auth codes ---

    def test_put_get_auth_code(self):
        store = self._make_store()
        store.put_auth_code("code1", {"type": "code", "client_id": "c1"})
        result = store.get_auth_code("code1")
        self.assertEqual(result["client_id"], "c1")

    def test_pop_auth_code_single_use(self):
        store = self._make_store()
        store.put_auth_code("code2", {"type": "code", "data": "x"})
        result = store.pop_auth_code("code2")
        self.assertIsNotNone(result)
        self.assertIsNone(store.pop_auth_code("code2"))

    def test_delete_auth_code(self):
        store = self._make_store()
        store.put_auth_code("code3", {"type": "pending"})
        store.delete_auth_code("code3")
        self.assertIsNone(store.get_auth_code("code3"))

    def test_auth_code_count(self):
        store = self._make_store()
        self.assertEqual(store.auth_code_count(), 0)
        store.put_auth_code("a", {"x": 1, "created_at": time.time()})
        store.put_auth_code("b", {"x": 2, "created_at": time.time()})
        self.assertEqual(store.auth_code_count(), 2)

    def test_nonexistent_auth_code_returns_none(self):
        store = self._make_store()
        self.assertIsNone(store.get_auth_code("nope"))
        self.assertIsNone(store.pop_auth_code("nope"))

    # --- Client registrations ---

    def test_put_get_client(self):
        store = self._make_store()
        store.put_client("client-1", {"name": "Test", "redirect_uris": ["http://localhost"]})
        result = store.get_client("client-1")
        self.assertEqual(result["name"], "Test")

    def test_nonexistent_client_returns_none(self):
        store = self._make_store()
        self.assertIsNone(store.get_client("no-such-client"))

    def test_client_count(self):
        store = self._make_store()
        self.assertEqual(store.client_count(), 0)
        store.put_client("c1", {"name": "A"})
        store.put_client("c2", {"name": "B"})
        self.assertEqual(store.client_count(), 2)

    # --- Refresh tokens ---

    def test_put_pop_refresh_token(self):
        store = self._make_store()
        store.put_refresh_token("rt-1", {"session_token": "s1", "created_at": time.time()}, ttl=3600)
        result = store.pop_refresh_token("rt-1")
        self.assertEqual(result["session_token"], "s1")
        # Second pop returns None
        self.assertIsNone(store.pop_refresh_token("rt-1"))

    def test_nonexistent_refresh_token_returns_none(self):
        store = self._make_store()
        self.assertIsNone(store.pop_refresh_token("no-such-rt"))

    # --- OAuth state (CSRF) ---

    def test_put_pop_oauth_state(self):
        store = self._make_store()
        now = time.time()
        store.put_oauth_state("state-1", now, ttl=600)
        result = store.pop_oauth_state("state-1")
        self.assertEqual(result, now)
        # Second pop returns None
        self.assertIsNone(store.pop_oauth_state("state-1"))

    def test_oauth_state_count(self):
        store = self._make_store()
        self.assertEqual(store.oauth_state_count(), 0)
        store.put_oauth_state("s1", time.time(), ttl=600)
        store.put_oauth_state("s2", time.time(), ttl=600)
        self.assertEqual(store.oauth_state_count(), 2)

    def test_expired_oauth_states_cleaned_on_put(self):
        store = self._make_store()
        # Add an expired state
        store.put_oauth_state("old", time.time() - 700, ttl=600)
        # Adding a new state triggers cleanup
        store.put_oauth_state("new", time.time(), ttl=600)
        # Old state should have been cleaned
        self.assertIsNone(store.pop_oauth_state("old"))
        # New state should be present
        self.assertIsNotNone(store.pop_oauth_state("new"))


class TestOAuthStateStoreBase(unittest.TestCase):
    """Verify base class raises NotImplementedError."""

    def test_base_methods_raise(self):
        from redis_store import OAuthStateStoreBase
        base = OAuthStateStoreBase()

        with self.assertRaises(NotImplementedError):
            base.put_auth_code("c", {})
        with self.assertRaises(NotImplementedError):
            base.get_auth_code("c")
        with self.assertRaises(NotImplementedError):
            base.pop_auth_code("c")
        with self.assertRaises(NotImplementedError):
            base.delete_auth_code("c")
        with self.assertRaises(NotImplementedError):
            base.auth_code_count()
        with self.assertRaises(NotImplementedError):
            base.put_client("c", {})
        with self.assertRaises(NotImplementedError):
            base.get_client("c")
        with self.assertRaises(NotImplementedError):
            base.client_count()
        with self.assertRaises(NotImplementedError):
            base.put_refresh_token("t", {}, 600)
        with self.assertRaises(NotImplementedError):
            base.pop_refresh_token("t")
        with self.assertRaises(NotImplementedError):
            base.put_oauth_state("s", 0.0)
        with self.assertRaises(NotImplementedError):
            base.pop_oauth_state("s")
        with self.assertRaises(NotImplementedError):
            base.oauth_state_count()


if __name__ == "__main__":
    unittest.main()
