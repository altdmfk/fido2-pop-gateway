import time
import uuid
import threading
from typing import Dict

class NonceStore:
    def __init__(self, ttl: int = 60):
        self.ttl = ttl
        self._store: Dict[str, float] = {}
        self._lock = threading.Lock()

    def issue_nonce(self) -> str:
        nonce = str(uuid.uuid4())
        with self._lock:
            self._store[nonce] = time.time()
        return nonce

    def consume_nonce(self, nonce: str) -> str:
        with self._lock:
            issued_time = self._store.get(nonce)
            if issued_time is None:
                return "invalid"
            
            if time.time() - issued_time > self.ttl:
                self._store.pop(nonce, None)
                return "expired"
                
            self._store.pop(nonce)
            return "valid"

    def cleanup(self):
        with self._lock:
            current_time = time.time()
            expired = [n for n, t in self._store.items() if current_time - t > self.ttl]
            for n in expired:
                del self._store[n]

nonce_store = NonceStore()
