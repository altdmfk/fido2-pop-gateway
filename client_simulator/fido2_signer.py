import base64
import hashlib
import time
from typing import Dict, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


class FIDO2ClientSimulator:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.credential_id = base64.urlsafe_b64encode(hashlib.sha256(str(time.time()).encode()).digest()).decode().rstrip("=")

    def get_public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def generate_canonical_payload(
        self,
        method: str,
        host: str,
        path: str,
        *,
        query: str = "",
        body: bytes = b"",
        nonce: str = "",
        timestamp: int = 0,
    ) -> bytes:
        body_hash = hashlib.sha256(body).hexdigest()
        canonical_str = f"{method.upper()}\n{host}\n{path}\n{query}\n{body_hash}\n{nonce}\n{timestamp}"
        return canonical_str.encode("utf-8")

    def sign_request(
        self,
        method: str,
        host: str,
        path: str,
        *,
        query: str = "",
        body: bytes = b"",
        nonce: str = "",
    ) -> Tuple[Dict[str, str], bytes]:
        timestamp = int(time.time())
        payload = self.generate_canonical_payload(
            method, host, path, query=query, body=body, nonce=nonce, timestamp=timestamp
        )

        signature = self.private_key.sign(
            payload,
            ec.ECDSA(hashes.SHA256()),
        )

        # Convert DER signature into raw IEEE P1363 (r || s) 64-byte representation
        r, s = decode_dss_signature(signature)
        raw_signature = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")
        signature_b64 = base64.urlsafe_b64encode(raw_signature).decode().rstrip("=")
        body_hash = hashlib.sha256(body).hexdigest()

        headers = {
            "Host": host,
            "X-FIDO2-Credential-ID": self.credential_id,
            "X-FIDO2-Signature": signature_b64,
            "X-FIDO2-Nonce": nonce,
            "X-FIDO2-Timestamp": str(timestamp),
            "X-Body-Digest": f"sha256={body_hash}",
        }
        return headers, payload


if __name__ == "__main__":
    import json

    simulator = FIDO2ClientSimulator()
    method = "GET"
    host = "127.0.0.1:8000"
    path = "/api/v1/resource"
    headers, payload = simulator.sign_request(method, host, path, query="", body=b"", nonce="demo-nonce-1234")
    print("Generated FIDO2 PoP Headers:")
    print(json.dumps(headers, indent=4))
