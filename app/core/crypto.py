import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding

def generate_canonical_payload(
    method: str,
    path: str,
    *,
    query: str = "",
    body: bytes = b"",
    body_hash: str = None,
    nonce: str = "",
    timestamp: int = 0
) -> bytes:
    if body_hash is None:
        body_hash = hashlib.sha256(body).hexdigest()
    canonical_str = f"{method.upper()}|{path}|{query}|{body_hash}|{nonce}|{timestamp}"
    return canonical_str.encode("utf-8")

def verify_pop_signature(public_key_pem: bytes, signature: bytes, canonical_payload: bytes) -> bool:
    try:
        public_key = load_pem_public_key(public_key_pem)
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature,
                canonical_payload,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                canonical_payload,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        return False
    except (InvalidSignature, ValueError):
        return False
