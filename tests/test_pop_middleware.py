import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
import httpx
from app.main import app
from client_simulator.fido2_signer import FIDO2ClientSimulator

client = TestClient(app)

@pytest.fixture
def mock_upstream():
    with patch("httpx.AsyncClient.send") as mock_send:
        # Create an async iterator for StreamingResponse
        async def mock_aiter_raw():
            yield b'{"status": "success", "data": "mocked upstream response"}'
            
        mock_response = httpx.Response(200)
        mock_response.aiter_raw = mock_aiter_raw
        mock_send.return_value = mock_response
        yield mock_send

@pytest.fixture
def setup_client():
    # 1. Login to get JWT
    resp = client.post("/auth/token", data={"username": "testuser", "password": "secret"})
    jwt_token = resp.json()["access_token"]
    
    # 2. Get Nonce
    resp = client.get("/auth/nonce")
    nonce = resp.json()["nonce"]
    
    # 3. Register FIDO2 Key
    simulator = FIDO2ClientSimulator()
    client.post(
        "/auth/register-key", 
        json={"credential_id": simulator.credential_id, "public_key_pem": simulator.get_public_key_pem()},
        headers={"Authorization": f"Bearer {jwt_token}"}
    )
    
    return simulator, jwt_token, nonce

def test_success_flow(setup_client, mock_upstream):
    simulator, jwt_token, nonce = setup_client
    
    method = "GET"
    path = "/api/v1/resource"
    body = b""
    
    pop_headers, _ = simulator.sign_request(method, path, body=body, nonce=nonce)
    headers = {"Authorization": f"Bearer {jwt_token}"}
    headers.update(pop_headers)
    
    response = client.get(path, headers=headers)
    assert response.status_code == 200

def test_token_only_theft(setup_client, mock_upstream):
    _, jwt_token, _ = setup_client
    
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = client.get("/api/v1/resource", headers=headers)
    
    assert response.status_code == 401
    assert "Missing required FIDO2 PoP headers" in response.text

def test_replay_attack(setup_client, mock_upstream):
    simulator, jwt_token, nonce = setup_client
    
    method = "GET"
    path = "/api/v1/resource"
    body = b""
    
    pop_headers, _ = simulator.sign_request(method, path, body=body, nonce=nonce)
    headers = {"Authorization": f"Bearer {jwt_token}"}
    headers.update(pop_headers)
    
    # Request 1 (Valid)
    response1 = client.get(path, headers=headers)
    assert response1.status_code == 200
    
    # Request 2 (Replay, identical request)
    response2 = client.get(path, headers=headers)
    assert response2.status_code == 401
    assert "Invalid or replayed nonce" in response2.text

def test_payload_tampering(setup_client, mock_upstream):
    simulator, jwt_token, nonce = setup_client
    
    method = "GET"
    path = "/api/v1/resource"
    body = b""
    
    pop_headers, _ = simulator.sign_request(method, path, body=body, nonce=nonce)
    headers = {"Authorization": f"Bearer {jwt_token}"}
    headers.update(pop_headers)
    
    # Attacker intercepts and modifies the path
    tampered_path = "/api/v1/admin"
    response = client.get(tampered_path, headers=headers)
    
    assert response.status_code == 403
    assert "Invalid FIDO2 PoP signature" in response.text

def test_missing_body_digest_header(setup_client, mock_upstream):
    simulator, jwt_token, nonce = setup_client
    
    method = "POST"
    path = "/api/v1/resource"
    body = b'{"data": "test"}'
    
    pop_headers, _ = simulator.sign_request(method, path, body=body, nonce=nonce)
    headers = {"Authorization": f"Bearer {jwt_token}"}
    headers.update(pop_headers)
    
    # Remove X-Body-Digest header intentionally
    if "X-Body-Digest" in headers:
        del headers["X-Body-Digest"]
        
    response = client.post(path, headers=headers, content=body)
    assert response.status_code == 400
    assert "Missing or invalid X-Body-Digest header" in response.text

def test_invalid_body_digest_header(setup_client, mock_upstream):
    simulator, jwt_token, nonce = setup_client
    
    method = "POST"
    path = "/api/v1/resource"
    body = b'{"data": "test"}'
    
    pop_headers, _ = simulator.sign_request(method, path, body=body, nonce=nonce)
    headers = {"Authorization": f"Bearer {jwt_token}"}
    headers.update(pop_headers)
    
    # Intentionally provide a tampered digest
    headers["X-Body-Digest"] = "sha256=abcdef1234567890"
    
    response = client.post(path, headers=headers, content=body)
    assert response.status_code == 400
    assert "Body digest mismatch" in response.text
