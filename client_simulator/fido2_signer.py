import hashlib
import time
import base64
from typing import Tuple, Dict
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

class FIDO2ClientSimulator:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.credential_id = base64.urlsafe_b64encode(hashlib.sha256(str(time.time()).encode()).digest()).decode().rstrip("=")

    def get_public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def generate_canonical_payload(self, method: str, path: str, *args, query: str = "", body: bytes = b"", nonce: str = "", timestamp: int = 0) -> bytes:
        if len(args) == 3:
            body, nonce, timestamp = args
        elif len(args) == 4:
            query, body, nonce, timestamp = args
        body_hash = hashlib.sha256(body).hexdigest()
        canonical_str = f"{method.upper()}|{path}|{query}|{body_hash}|{nonce}|{timestamp}"
        return canonical_str.encode("utf-8")

    def sign_request(self, method: str, path: str, *args, query: str = "", body: bytes = b"", nonce: str = "") -> Tuple[Dict[str, str], bytes]:
        if len(args) == 2:
            body, nonce = args
        elif len(args) == 3:
            query, body, nonce = args
        timestamp = int(time.time())
        payload = self.generate_canonical_payload(method, path, query=query, body=body, nonce=nonce, timestamp=timestamp)
        
        signature = self.private_key.sign(
            payload,
            ec.ECDSA(hashes.SHA256())
        )
        
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        
        headers = {
            "X-FIDO2-Credential-ID": self.credential_id,
            "X-FIDO2-Signature": signature_b64,
            "X-FIDO2-Nonce": nonce,
            "X-FIDO2-Timestamp": str(timestamp)
        }
        return headers, payload

if __name__ == "__main__":
    import json
    
    # 1. Instantiate FIDO2ClientSimulator
    simulator = FIDO2ClientSimulator()
    
    # 2. Generate dummy values
    method = "GET"
    path = "/api/v1/resource"
    query = ""
    body = b""
    nonce = "demo-nonce-1234"
    
    # 3. Call sign_request to generate headers
    headers, payload = simulator.sign_request(method, path, query, body, nonce)
    
    # 4. Pretty-print the resulting dictionary
    print("Generated FIDO2 PoP Headers:")
    print(json.dumps(headers, indent=4))
    
    # 5. Print clear confirmation message
    print("\n[INFO] FIDO2 client simulation executed successfully.")
