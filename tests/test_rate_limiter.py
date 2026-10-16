import pytest
import time
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_rate_limiter():
    # Allow test to run in isolation without overlapping with other tests
    time.sleep(1.1)

    # 1. 10 requests within the threshold -> all succeed
    for _ in range(10):
        response = client.get("/auth/nonce")
        assert response.status_code == 200
        assert "nonce" in response.json()

    # 2. The 11th request -> fails with 429
    response = client.get("/auth/nonce")
    assert response.status_code == 429
    assert response.headers.get("Retry-After") == "1"
    json_resp = response.json()
    assert json_resp["error"] == "rate_limit_exceeded"
    assert json_resp["message"] == "Too many nonce requests. Please retry later."

    # 3. Wait window interval (1 second) -> request succeeds again
    time.sleep(1.1)
    response = client.get("/auth/nonce")
    assert response.status_code == 200
    assert "nonce" in response.json()


def test_rate_limiter_stale_ip_cleanup():
    from app.core.rate_limiter import NonceRateLimiter

    limiter = NonceRateLimiter(limit=5, window=0.5, max_tracked_ips=10)
    # Record requests from multiple IPs
    assert limiter.is_allowed("10.0.0.1") is True
    assert limiter.is_allowed("10.0.0.2") is True
    assert "10.0.0.1" in limiter.records
    assert "10.0.0.2" in limiter.records

    # Before window expires, cleanup does not remove active IPs
    pruned = limiter.cleanup()
    assert pruned == 0

    # Wait past window interval
    time.sleep(0.6)

    # Cleanup should prune stale IPs to prevent memory leak
    pruned = limiter.cleanup()
    assert pruned == 2
    assert "10.0.0.1" not in limiter.records
    assert "10.0.0.2" not in limiter.records


def test_nonce_store_capacity_and_hygiene():
    from app.core.nonce_store import NonceStore

    store = NonceStore(ttl=1, max_entries=5)

    # Issue nonces up to capacity
    nonces = [store.issue_nonce() for _ in range(5)]
    assert len(store._store) == 5

    # Issue another nonce: expired nonces aren't yet expired, so oldest should be evicted
    store.issue_nonce()
    assert len(store._store) <= 5

    # Let TTL expire
    time.sleep(1.1)
    pruned = store.cleanup()
    assert pruned > 0
    assert len(store._store) == 0

