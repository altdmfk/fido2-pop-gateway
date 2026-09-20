import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding

def generate_canonical_payload(
    method: str,
    host: str,
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
    # Using strict newline delimiters and including host to prevent collision and cross-host attacks
    canonical_str = f"{method.upper()}\n{host}\n{path}\n{query}\n{body_hash}\n{nonce}\n{timestamp}"
    return canonical_str.encode("utf-8")

import logging
from cryptography.exceptions import UnsupportedAlgorithm

logger = logging.getLogger(__name__)

def verify_pop_signature(public_key_pem: bytes, signature: bytes, canonical_payload: bytes) -> bool:
    try:
        try:
            public_key = load_pem_public_key(public_key_pem)
        except (ValueError, TypeError, UnsupportedAlgorithm) as e:
            logger.error(f"Failed to load public key: {e}")
            return False

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
        else:
            logger.warning(f"Unsupported key type: {type(public_key).__name__}")
            return False
    except InvalidSignature:
        return False
    except Exception as e:
        logger.error(f"Unexpected error during signature verification: {e}")
        return False
