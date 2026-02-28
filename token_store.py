"""
Encrypted token storage for per-user Salesforce OAuth credentials.

Stores a mapping of API key -> {access_token, refresh_token, instance_url, ...}
encrypted at rest using Fernet symmetric encryption (cryptography library).

Storage file: data/tokens.json.enc
Encryption key: ENCRYPTION_KEY env var (Fernet key, 32 bytes URL-safe base64)

Generate a key with:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

import hashlib
import json
import os
import logging
import tempfile
import threading
from pathlib import Path
from typing import TypedDict

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

TOKEN_FILE = Path(__file__).parent / "data" / "tokens.json.enc"


class UserTokens(TypedDict):
    access_token: str
    refresh_token: str
    instance_url: str
    issued_at: float
    pardot_business_unit_id: str | None  # None = use shared env var


def _hash_key(api_key: str) -> str:
    """Hash API key with SHA-256 for use as dict key (avoids storing plaintext keys)."""
    return hashlib.sha256(api_key.encode()).hexdigest()


class TokenStore:
    """Thread-safe encrypted token storage."""

    def __init__(self) -> None:
        key = os.environ.get("ENCRYPTION_KEY")
        if not key:
            raise RuntimeError("ENCRYPTION_KEY env var is required for multi-tenant mode")
        self._fernet = Fernet(key.encode())
        self._lock = threading.Lock()
        self._cache: dict[str, UserTokens] | None = None

    def _ensure_dir(self) -> None:
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict[str, UserTokens]:
        if self._cache is not None:
            return self._cache
        if not TOKEN_FILE.exists():
            self._cache = {}
            return self._cache
        encrypted = TOKEN_FILE.read_bytes()
        decrypted = self._fernet.decrypt(encrypted)
        self._cache = json.loads(decrypted)
        return self._cache

    def _save(self, data: dict[str, UserTokens]) -> None:
        self._ensure_dir()
        plaintext = json.dumps(data).encode()
        encrypted = self._fernet.encrypt(plaintext)
        # Atomic write: write to temp file then rename
        fd, tmp_path = tempfile.mkstemp(dir=TOKEN_FILE.parent)
        try:
            os.write(fd, encrypted)
            os.close(fd)
            fd = -1  # mark as closed
            os.replace(tmp_path, TOKEN_FILE)
        except Exception:
            if fd >= 0:
                os.close(fd)
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
        self._cache = data

    def get(self, api_key: str) -> UserTokens | None:
        """Get stored tokens for an API key, or None if not connected."""
        hk = _hash_key(api_key)
        with self._lock:
            data = self._load()
            return data.get(hk)

    def put(self, api_key: str, tokens: UserTokens) -> None:
        """Store or update tokens for an API key."""
        hk = _hash_key(api_key)
        with self._lock:
            data = self._load()
            data[hk] = tokens
            self._save(data)

    def delete(self, api_key: str) -> bool:
        """Remove tokens for an API key. Returns True if found."""
        hk = _hash_key(api_key)
        with self._lock:
            data = self._load()
            if hk in data:
                del data[hk]
                self._save(data)
                return True
            return False

    def has_tokens(self, api_key: str) -> bool:
        """Check if an API key has stored OAuth tokens."""
        hk = _hash_key(api_key)
        with self._lock:
            return hk in self._load()


# Singleton (lazily initialized)
_store: TokenStore | None = None


def get_token_store() -> TokenStore | None:
    """Return the token store, or None if ENCRYPTION_KEY is not set (legacy mode)."""
    global _store
    if _store is None:
        if os.environ.get("ENCRYPTION_KEY"):
            _store = TokenStore()
        else:
            return None
    return _store
