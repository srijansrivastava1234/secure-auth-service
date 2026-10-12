import os
import time
from typing import Optional
import redis

REDIS_URL = os.getenv("REDIS_URL", "memory://")


class TokenBlacklist:
    def __init__(self, url: str):
        self.is_memory = url.startswith("memory://") or not url.startswith("redis://")
        if self.is_memory:
            self._storage = {}  # {jti: expiry_timestamp}
        else:
            self._client = redis.Redis.from_url(url, decode_responses=True)

    def revoke_token(self, jti: str, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        if self.is_memory:
            self._storage[jti] = time.time() + ttl_seconds
        else:
            try:
                self._client.setex(f"blacklist:{jti}", ttl_seconds, "revoked")
            except redis.RedisError as e:
                # Fail-closed: log and re-raise or raise HTTP 503 in route
                raise RuntimeError("Token revocation store unreachable") from e

    def is_blacklisted(self, jti: str) -> bool:
        if self.is_memory:
            expiry = self._storage.get(jti)
            if expiry is None:
                return False
            if time.time() > expiry:
                del self._storage[jti]
                return False
            return True
        else:
            try:
                return bool(self._client.exists(f"blacklist:{jti}"))
            except redis.RedisError as e:
                # Fail-closed security policy: Reject authentication if cache partition occurs
                raise RuntimeError("Security blacklist verification unreachable") from e

    def clear(self) -> None:
        """Helper for test isolation."""
        if self.is_memory:
            self._storage.clear()


blacklist_client = TokenBlacklist(REDIS_URL)
