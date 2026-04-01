"""Thread-safe in-memory cache for deduplicating concurrent settlement requests."""

from __future__ import annotations

import threading
import time


class SettlementCache:
    """In-memory cache for deduplicating concurrent settlement requests.

    Each entry carries its own TTL because TVM settlement validity depends on the
    request-specific timeout window.
    """

    def __init__(self) -> None:
        self._entries: dict[str, float] = {}
        self._lock = threading.Lock()

    def reserve(self, key: str, ttl_seconds: float) -> bool:
        """Return ``True`` when *key* is already pending; otherwise reserve it."""
        now = time.monotonic()
        expires_at = now + max(0.0, ttl_seconds)
        with self._lock:
            self._prune(now)
            if key in self._entries:
                return True
            self._entries[key] = expires_at
            return False

    def release(self, key: str) -> None:
        """Remove *key* from the pending settlement set."""
        with self._lock:
            self._entries.pop(key, None)

    @property
    def entries(self) -> dict[str, float]:
        """Direct access to the underlying dict for tests."""
        return self._entries

    def _prune(self, now: float) -> None:
        expired = [key for key, expires_at in self._entries.items() if expires_at <= now]
        for key in expired:
            del self._entries[key]
