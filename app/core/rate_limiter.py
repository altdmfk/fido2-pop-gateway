import threading
import time
from collections import deque
from typing import Dict, Optional

from app.core.config import settings


class NonceRateLimiter:
    """Sliding-window IP rate limiter with O(1) deque eviction.
    
    Uses collections.deque.popleft() to prune expired timestamp windows in O(1) time,
    minimizing critical section lock contention under high concurrent loads.
    Includes active memory hygiene to evict stale IP entries and prevent memory exhaustion.
    """

    def __init__(
        self,
        limit: Optional[int] = None,
        window: Optional[float] = None,
        max_tracked_ips: Optional[int] = None,
    ):
        self.limit = limit if limit is not None else settings.rate_limit_requests
        self.window = window if window is not None else settings.rate_limit_window_seconds
        self.max_tracked_ips = max_tracked_ips if max_tracked_ips is not None else settings.rate_limit_max_tracked_ips
        self.lock = threading.Lock()
        self.records: Dict[str, deque] = {}

    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        with self.lock:
            # Prevent unbounded growth from distributed or spoofed IP scanning
            if len(self.records) >= self.max_tracked_ips:
                self._cleanup_locked(now)

            history = self.records.get(client_ip)
            if history is None:
                history = deque()
                self.records[client_ip] = history

            # O(1) eviction of expired timestamps from the sliding window
            while history and now - history[0] > self.window:
                history.popleft()

            if len(history) < self.limit:
                history.append(now)
                return True

            return False

    def _cleanup_locked(self, now: float) -> int:
        stale_ips = [
            ip for ip, history in self.records.items()
            if not history or (now - history[-1] > self.window)
        ]
        for ip in stale_ips:
            self.records.pop(ip, None)
        return len(stale_ips)

    def cleanup(self) -> int:
        now = time.time()
        with self.lock:
            return self._cleanup_locked(now)


nonce_rate_limiter = NonceRateLimiter()
