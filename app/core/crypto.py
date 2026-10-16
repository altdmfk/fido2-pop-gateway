import hashlib
import logging
from typing import Optional

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

logger = logging.getLogger(__name__)


def generate_canonical_payload(
    method: str,
    host: str,
    path: str,
    *,
    query: str = "",
    body: bytes = b"",
    body_hash: Optional[str] = None,
    nonce: str = "",
    timestamp: int = 0,
) -> bytes:
    """Constructs a deterministic canonical payload for FAPI-grade signature binding.
    
    Format: Method \\n Host \\n Path \\n Query \\n BodyHash \\n Nonce \\n Timestamp
    Newline delimiters prevent field collision and cross-host confusion attacks.
    """
    if body_hash is None:
        body_hash = hashlib.sha256(body).hexdigest()

    canonical_str = f"{method.upper()}\n{host}\n{path}\n{query}\n{body_hash}\n{nonce}\n{timestamp}"
    return canonical_str.encode("utf-8")


def verify_pop_signature(public_key_pem: bytes, signature: bytes, canonical_payload: bytes) -> bool:
    """Verifies ECDSA P-256 or RSA-2048 Proof-of-Possession signatures.
    
    Note: OpenSSL C-extensions release the Python GIL during cryptographic operations,
    allowing anyio.to_thread / thread-pool delegation to utilize multiple CPU cores effectively.
    """
    try:
        public_key = load_pem_public_key(public_key_pem)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        logger.error(f"Failed to parse public key PEM: {exc}")
        return False

    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            # Convert 64-byte raw (r, s) IEEE P1363 WebAuthn/FIDO2 format into ASN.1 DER format
            if len(signature) == 64:
                r = int.from_bytes(signature[:32], byteorder="big")
                s = int.from_bytes(signature[32:], byteorder="big")
                signature = encode_dss_signature(r, s)

            public_key.verify(
                signature,
                canonical_payload,
                ec.ECDSA(hashes.SHA256()),
            )
            return True

        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                canonical_payload,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True

        logger.warning(f"Unsupported key type for PoP verification: {type(public_key).__name__}")
        return False

    except InvalidSignature:
        return False
    except Exception as exc:
        logger.error(f"Unexpected error during signature verification: {exc}")
        return False
