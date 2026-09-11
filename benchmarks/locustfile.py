import time
import base64
import hashlib
from typing import Dict, Tuple
from locust import HttpUser, task, between, events

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# --- FIDO2 Signer Helper ---
class LoadTestSigner:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        # Create a deterministic credential ID based on public key
        pk_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.credential_id = base64.urlsafe_b64encode(hashlib.sha256(pk_bytes).digest()).decode().rstrip("=")

    def get_public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def generate_canonical_payload(self, method: str, path: str, *, query: str = "", body: bytes = b"", nonce: str = "", timestamp: int = 0) -> bytes:
        body_hash = hashlib.sha256(body).hexdigest()
        canonical_str = f"{method.upper()}|{path}|{query}|{body_hash}|{nonce}|{timestamp}"
        return canonical_str.encode("utf-8")

    def sign_request(self, method: str, path: str, *, query: str = "", body: bytes = b"", nonce: str = "") -> Dict[str, str]:
        timestamp = int(time.time())
        payload = self.generate_canonical_payload(method, path, query=query, body=body, nonce=nonce, timestamp=timestamp)
        
        signature = self.private_key.sign(
            payload,
            ec.ECDSA(hashes.SHA256())
        )
        
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        
        body_hash = hashlib.sha256(body).hexdigest()
        
        return {
            "X-FIDO2-Credential-ID": self.credential_id,
            "X-FIDO2-Signature": signature_b64,
            "X-FIDO2-Nonce": nonce,
            "X-FIDO2-Timestamp": str(timestamp),
            "X-Body-Digest": f"sha256={body_hash}"
        }

class FIDO2User(HttpUser):
    # Wait between 0.1 to 0.5 seconds between tasks
    wait_time = between(0.1, 0.5)

    token = None

    def on_start(self):
        """
        Executed when a simulated user starts.
        We need to log in, get a JWT token, and register our FIDO2 credential.
        """
        self.signer = LoadTestSigner()
        
        if not FIDO2User.token:
            login_resp = self.client.post("/auth/token", data={"username": "testuser", "password": "secret"})
            if login_resp.status_code == 200:
                FIDO2User.token = login_resp.json().get("access_token")
            else:
                print(f"Login failed: {login_resp.text}")
        
        self.token = FIDO2User.token
        
        reg_resp = self.client.post(
            "/auth/register-key",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"credential_id": self.signer.credential_id, "public_key_pem": self.signer.get_public_key_pem()}
        )
        if reg_resp.status_code != 200:
            print(f"Credential registration failed: {reg_resp.text}")

    @task
    def access_protected_api(self):
        """
        The main load testing task.
        1. Fetch Nonce
        2. Sign request
        3. Access API
        """
        if not self.token:
            return

        # 1. Fetch a fresh Nonce
        import random
        fake_ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        nonce_resp = self.client.get("/auth/nonce", headers={"X-Forwarded-For": fake_ip})
        if nonce_resp.status_code != 200:
            return
            
        nonce = nonce_resp.json().get("nonce")
        
        # 2. Prepare API call details
        method = "GET"
        path = "/api/v1/resource" # Adjust to your actual endpoint
        query = ""
        body = b""
        
        # 3. Generate FIDO2 PoP headers
        pop_headers = self.signer.sign_request(method, path, query=query, body=body, nonce=nonce)
        
        # 4. Combine headers
        headers = {
            "Authorization": f"Bearer {self.token}",
            **pop_headers
        }
        
        # 5. Call protected API
        with self.client.request(
            method=method,
            url=path,
            headers=headers,
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed with {response.status_code}: {response.text}")
