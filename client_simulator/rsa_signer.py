import hashlib
import time
import base64
from typing import Tuple, Dict
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

class RSAPoPClientSimulator:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        self.credential_id = base64.urlsafe_b64encode(hashlib.sha256(str(time.time()).encode()).digest()).decode().rstrip("=")

    def get_public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def generate_canonical_payload(self, method: str, path: str, body: bytes, nonce: str, timestamp: int) -> bytes:
        body_hash = hashlib.sha256(body).hexdigest()
        canonical_str = f"{method.upper()}|{path}|{body_hash}|{nonce}|{timestamp}"
        return canonical_str.encode("utf-8")

    def sign_request(self, method: str, path: str, body: bytes, nonce: str) -> Tuple[Dict[str, str], bytes]:
        timestamp = int(time.time())
        payload = self.generate_canonical_payload(method, path, body, nonce, timestamp)
        
        signature = self.private_key.sign(
            payload,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        
        headers = {
            "X-FIDO2-Credential-ID": self.credential_id,
            "X-FIDO2-Signature": signature_b64,
            "X-FIDO2-Nonce": nonce,
            "X-FIDO2-Timestamp": str(timestamp)
        }
        return headers, payload
