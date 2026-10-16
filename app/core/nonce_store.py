import threading
import time
import uuid
from typing import Dict, Optional

from app.core.config import settings


class NonceStore:
    """Thread-safe, single-use cryptographic nonce cache.
    
    Protects against replay attacks by enforcing atomic single consumption (TOCTOU defense)
    and bounds memory consumption via proactive capacity-capped eviction.
    """

    def __init__(
        self,
        ttl: Optional[int] = None,
        max_entries: Optional[int] = None,
    ):
        self.ttl = ttl if ttl is not None else settings.nonce_ttl_seconds
        self.max_entries = max_entries if max_entries is not None else settings.nonce_max_entries
        self._store: Dict[str, float] = {}
        self._lock = threading.Lock()

    def issue_nonce(self) -> str:
        nonce = str(uuid.uuid4())
        now = time.time()
        with self._lock:
            # Prevent unbounded memory growth under sustained nonce generation load
            if len(self._store) >= self.max_entries:
                self._purge_expired_locked(now)
                if len(self._store) >= self.max_entries:
                    # Evict oldest 10% when full despite expired purge
                    evict_count = max(1, self.max_entries // 10)
                    oldest_keys = sorted(self._store.keys(), key=lambda k: self._store[k])[:evict_count]
                    for k in oldest_keys:
                        self._store.pop(k, None)
            self._store[nonce] = now
        return nonce

    def consume_nonce(self, nonce: str) -> str:
        with self._lock:
            issued_time = self._store.get(nonce)
            if issued_time is None:
                return "invalid"

            # Always remove the nonce once read to guarantee strict single-use semantics
            self._store.pop(nonce, None)

            if time.time() - issued_time > self.ttl:
                return "expired"

            return "valid"

    def _purge_expired_locked(self, now: float) -> int:
        expired_keys = [n for n, t in self._store.items() if now - t > self.ttl]
        for n in expired_keys:
            self._store.pop(n, None)
        return len(expired_keys)

    def cleanup(self) -> int:
        now = time.time()
        with self._lock:
            return self._purge_expired_locked(now)


nonce_store = NonceStore()
