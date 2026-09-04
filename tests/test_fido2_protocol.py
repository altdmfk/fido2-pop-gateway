import pytest
import time
import base64
from app.core.crypto import generate_canonical_payload, verify_pop_signature
from client_simulator.fido2_signer import FIDO2ClientSimulator

def test_canonical_payload_generation():
    method = "POST"
    path = "/api/v1/resource"
    body = b'{"data": "test"}'
    nonce = "test-nonce-123"
    timestamp = 1600000000

    payload = generate_canonical_payload(method, path, body, nonce, timestamp)
    import hashlib
    expected_hash = hashlib.sha256(b'{"data": "test"}').hexdigest()
    expected = f"POST|/api/v1/resource|{expected_hash}|test-nonce-123|1600000000".encode("utf-8")
    assert payload == expected

def test_client_simulator_signing_and_verification():
    client = FIDO2ClientSimulator()
    pub_key_pem = client.get_public_key_pem()

    method = "GET"
    path = "/api/v1/data"
    body = b""
    nonce = "server-nonce-xyz"

    headers, payload = client.sign_request(method, path, body, nonce)
    
    assert "X-FIDO2-Credential-ID" in headers
    assert "X-FIDO2-Signature" in headers
    assert "X-FIDO2-Nonce" in headers
    assert "X-FIDO2-Timestamp" in headers

    signature_bytes = base64.urlsafe_b64decode(headers["X-FIDO2-Signature"] + "===")
    
    # Server side verification
    is_valid = verify_pop_signature(pub_key_pem.encode("utf-8"), signature_bytes, payload)
    assert is_valid is True

def test_verification_fails_on_tampered_payload():
    client = FIDO2ClientSimulator()
    pub_key_pem = client.get_public_key_pem()

    method = "GET"
    path = "/api/v1/data"
    body = b""
    nonce = "server-nonce-xyz"

    headers, payload = client.sign_request(method, path, body, nonce)
    signature_bytes = base64.urlsafe_b64decode(headers["X-FIDO2-Signature"] + "===")
    
    # Tamper payload
    tampered_payload = payload + b"-tampered"
    
    is_valid = verify_pop_signature(pub_key_pem.encode("utf-8"), signature_bytes, tampered_payload)
    assert is_valid is False
