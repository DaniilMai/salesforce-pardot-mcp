"""
Redis-backed storage for OAuth tokens and MCP OAuth state.

RedisTokenStore: Fernet-encrypted user tokens with Redis native TTL.
RedisOAuthStateStore: MCP OAuth auth codes, client registrations, refresh tokens.
InMemoryOAuthStateStore: Fallback when REDIS_URL is not set.
"""

import json
import os
import time
import logging
from typing import Any

import redis
from cryptography.fernet import Fernet

from token_store import TokenStoreBase, UserTokens, _hash_key, _hash_key_legacy, SESSION_TTL_SECONDS

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Redis token store
# ---------------------------------------------------------------------------


class RedisTokenStore(TokenStoreBase):
    """Fernet-encrypted token storage in Redis with native TTL."""

    def __init__(self, redis_url: str) -> None:
        key = os.environ.get("ENCRYPTION_KEY")
        if not key:
            raise RuntimeError("ENCRYPTION_KEY required for RedisTokenStore")
        self._fernet = Fernet(key.encode())
        self._redis = redis.Redis.from_url(
            redis_url,
            decode_responses=False,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
        )
        self._prefix = "mcp:token:"

    def _rkey(self, api_key: str) -> str:
        return self._prefix + _hash_key(api_key)

    def _rkey_legacy(self, api_key: str) -> str:
        return self._prefix + _hash_key_legacy(api_key)

    def get(self, api_key: str) -> UserTokens | None:
        rk = self._rkey(api_key)
        data = self._redis.get(rk)

        # Legacy hash migration
        if data is None:
            rk_legacy = self._rkey_legacy(api_key)
            data = self._redis.get(rk_legacy)
            if data is not None:
                # Migrate: store under new key, delete old
                ttl = self._redis.ttl(rk_legacy)
                if ttl and ttl > 0:
                    self._redis.setex(rk, ttl, data)
                else:
                    self._redis.set(rk, data, ex=SESSION_TTL_SECONDS)
                self._redis.delete(rk_legacy)
                logger.info("Migrated Redis token entry from legacy hash to HMAC hash")

        if data is None:
            return None
        decrypted = self._fernet.decrypt(data)
        return json.loads(decrypted)

    def put(self, api_key: str, tokens: UserTokens) -> None:
        plaintext = json.dumps(tokens).encode()
        encrypted = self._fernet.encrypt(plaintext)
        self._redis.setex(self._rkey(api_key), SESSION_TTL_SECONDS, encrypted)

    def delete(self, api_key: str) -> bool:
        count = self._redis.delete(self._rkey(api_key))
        count += self._redis.delete(self._rkey_legacy(api_key))
        return count > 0

    def has_tokens(self, api_key: str) -> bool:
        return self.get(api_key) is not None


# ---------------------------------------------------------------------------
# OAuth state store interface
# ---------------------------------------------------------------------------


class OAuthStateStoreBase:
    """Interface for MCP OAuth ephemeral state storage."""

    # --- Auth codes ---
    def put_auth_code(self, code: str, data: dict, ttl: int = 600) -> None:
        raise NotImplementedError

    def get_auth_code(self, code: str) -> dict | None:
        raise NotImplementedError

    def pop_auth_code(self, code: str) -> dict | None:
        raise NotImplementedError

    def delete_auth_code(self, code: str) -> None:
        raise NotImplementedError

    def auth_code_count(self) -> int:
        raise NotImplementedError

    # --- Client registrations ---
    def put_client(self, client_id: str, data: dict) -> None:
        raise NotImplementedError

    def get_client(self, client_id: str) -> dict | None:
        raise NotImplementedError

    def client_count(self) -> int:
        raise NotImplementedError

    # --- Refresh tokens ---
    def put_refresh_token(self, token: str, data: dict, ttl: int) -> None:
        raise NotImplementedError

    def pop_refresh_token(self, token: str) -> dict | None:
        raise NotImplementedError

    # --- Legacy OAuth state (CSRF) ---
    def put_oauth_state(self, state: str, created_at: float, ttl: int = 600) -> None:
        raise NotImplementedError

    def pop_oauth_state(self, state: str) -> float | None:
        raise NotImplementedError

    def oauth_state_count(self) -> int:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Redis OAuth state store
# ---------------------------------------------------------------------------


class RedisOAuthStateStore(OAuthStateStoreBase):
    """Redis-backed MCP OAuth state with native TTL."""

    def __init__(self, redis_url: str) -> None:
        self._redis = redis.Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
        )

    # --- Auth codes ---

    def put_auth_code(self, code: str, data: dict, ttl: int = 600) -> None:
        self._redis.setex(f"mcp:authcode:{code}", ttl, json.dumps(data))

    def get_auth_code(self, code: str) -> dict | None:
        raw = self._redis.get(f"mcp:authcode:{code}")
        return json.loads(raw) if raw else None

    def pop_auth_code(self, code: str) -> dict | None:
        pipe = self._redis.pipeline()
        pipe.get(f"mcp:authcode:{code}")
        pipe.delete(f"mcp:authcode:{code}")
        result = pipe.execute()
        return json.loads(result[0]) if result[0] else None

    def delete_auth_code(self, code: str) -> None:
        self._redis.delete(f"mcp:authcode:{code}")

    def auth_code_count(self) -> int:
        count = 0
        for _ in self._redis.scan_iter(match="mcp:authcode:*", count=100):
            count += 1
        return count

    # --- Client registrations ---

    def put_client(self, client_id: str, data: dict) -> None:
        self._redis.set(f"mcp:client:{client_id}", json.dumps(data))

    def get_client(self, client_id: str) -> dict | None:
        raw = self._redis.get(f"mcp:client:{client_id}")
        return json.loads(raw) if raw else None

    def client_count(self) -> int:
        count = 0
        for _ in self._redis.scan_iter(match="mcp:client:*", count=100):
            count += 1
        return count

    # --- Refresh tokens ---

    def put_refresh_token(self, token: str, data: dict, ttl: int) -> None:
        self._redis.setex(f"mcp:refresh:{token}", ttl, json.dumps(data))

    def pop_refresh_token(self, token: str) -> dict | None:
        pipe = self._redis.pipeline()
        pipe.get(f"mcp:refresh:{token}")
        pipe.delete(f"mcp:refresh:{token}")
        result = pipe.execute()
        return json.loads(result[0]) if result[0] else None

    # --- Legacy OAuth state (CSRF) ---

    def put_oauth_state(self, state: str, created_at: float, ttl: int = 600) -> None:
        self._redis.setex(f"mcp:oauth_state:{state}", ttl, str(created_at))

    def pop_oauth_state(self, state: str) -> float | None:
        pipe = self._redis.pipeline()
        pipe.get(f"mcp:oauth_state:{state}")
        pipe.delete(f"mcp:oauth_state:{state}")
        result = pipe.execute()
        return float(result[0]) if result[0] else None

    def oauth_state_count(self) -> int:
        count = 0
        for _ in self._redis.scan_iter(match="mcp:oauth_state:*", count=100):
            count += 1
        return count


# ---------------------------------------------------------------------------
# In-memory fallback (same behavior as current dicts)
# ---------------------------------------------------------------------------


class InMemoryOAuthStateStore(OAuthStateStoreBase):
    """In-memory OAuth state store for backward compatibility without Redis."""

    def __init__(self) -> None:
        self._auth_codes: dict[str, dict] = {}
        self._clients: dict[str, dict] = {}
        self._refresh_tokens: dict[str, dict] = {}
        self._oauth_states: dict[str, float] = {}

    def _cleanup_expired(self, store: dict, ttl_key: str = "created_at", max_age: float | None = None) -> None:
        if max_age is None:
            return
        now = time.time()
        expired = [k for k, v in store.items() if now - v.get(ttl_key, 0) > max_age]
        for k in expired:
            del store[k]

    # --- Auth codes ---

    def put_auth_code(self, code: str, data: dict, ttl: int = 600) -> None:
        self._cleanup_expired(self._auth_codes, max_age=ttl)
        self._auth_codes[code] = data

    def get_auth_code(self, code: str) -> dict | None:
        return self._auth_codes.get(code)

    def pop_auth_code(self, code: str) -> dict | None:
        return self._auth_codes.pop(code, None)

    def delete_auth_code(self, code: str) -> None:
        self._auth_codes.pop(code, None)

    def auth_code_count(self) -> int:
        return len(self._auth_codes)

    # --- Client registrations ---

    def put_client(self, client_id: str, data: dict) -> None:
        self._clients[client_id] = data

    def get_client(self, client_id: str) -> dict | None:
        return self._clients.get(client_id)

    def client_count(self) -> int:
        return len(self._clients)

    # --- Refresh tokens ---

    def put_refresh_token(self, token: str, data: dict, ttl: int) -> None:
        self._cleanup_expired(self._refresh_tokens, max_age=ttl)
        data.setdefault("created_at", time.time())
        self._refresh_tokens[token] = data

    def pop_refresh_token(self, token: str) -> dict | None:
        return self._refresh_tokens.pop(token, None)

    # --- Legacy OAuth state (CSRF) ---

    def put_oauth_state(self, state: str, created_at: float, ttl: int = 600) -> None:
        # Cleanup expired states
        now = time.time()
        expired = [s for s, ts in self._oauth_states.items() if now - ts > ttl]
        for s in expired:
            del self._oauth_states[s]
        self._oauth_states[state] = created_at

    def pop_oauth_state(self, state: str) -> float | None:
        return self._oauth_states.pop(state, None)

    def oauth_state_count(self) -> int:
        return len(self._oauth_states)
