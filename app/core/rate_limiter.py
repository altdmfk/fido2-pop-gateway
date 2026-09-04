import time
import threading
from collections import defaultdict

class NonceRateLimiter:
    def __init__(self, limit: int = 10, window: float = 1.0):
        self.limit = limit
        self.window = window
        self.lock = threading.Lock()
        self.records = defaultdict(list)
    
    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        with self.lock:
            history = self.records[client_ip]
            
            # Remove timestamps older than the window
            while history and now - history[0] > self.window:
                history.pop(0)
            
            if len(history) < self.limit:
                history.append(now)
                return True
            return False

# Global instance for the gateway
nonce_rate_limiter = NonceRateLimiter(limit=10, window=1.0)
