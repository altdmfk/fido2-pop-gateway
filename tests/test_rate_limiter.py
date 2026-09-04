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
