import base64
import binascii
import hashlib
import hmac
import tempfile
import time

from anyio import to_thread
from fastapi import Request
from fastapi.responses import JSONResponse
import jwt

from app.core.config import settings
from app.core.credential_store import get_credential
from app.core.crypto import generate_canonical_payload, verify_pop_signature
from app.core.nonce_store import nonce_store
from app.core.security import decode_token


async def pop_middleware(request: Request, call_next):
    if not request.url.path.startswith("/api/"):
        return await call_next(request)

    # 1. Bearer Token Verification
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Missing or invalid authorization header"})

    token = auth_header.split(" ")[1]
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        request.state.user = user_id
        request.state.role = payload.get("role")
    except jwt.ExpiredSignatureError:
        return JSONResponse(status_code=401, content={"detail": "Token has expired"})
    except jwt.PyJWTError:
        return JSONResponse(status_code=401, content={"detail": "Invalid token"})

    # Benchmark bypass for pure Bearer JWT performance baseline (Mode A)
    if request.url.path == "/api/v1/baseline-jwt":
        return await call_next(request)

    # 2. Fast-Fail Header Presence & Timestamp Freshness
    cred_id = request.headers.get("X-FIDO2-Credential-ID")
    signature_b64 = request.headers.get("X-FIDO2-Signature")
    nonce = request.headers.get("X-FIDO2-Nonce")
    timestamp_str = request.headers.get("X-FIDO2-Timestamp")

    if not all([cred_id, signature_b64, nonce, timestamp_str]):
        return JSONResponse(status_code=401, content={"detail": "Missing required FIDO2 PoP headers"})

    try:
        timestamp = int(timestamp_str)
    except ValueError:
        return JSONResponse(status_code=401, content={"detail": "Invalid timestamp format"})

    current_time = int(time.time())
    if abs(current_time - timestamp) > settings.timestamp_tolerance_seconds:
        return JSONResponse(status_code=401, content={"detail": "Timestamp expired"})

    # 3. Nonce Single-Use Consumption (Anti-Replay)
    nonce_status = nonce_store.consume_nonce(nonce)
    if nonce_status == "invalid":
        return JSONResponse(status_code=401, content={"detail": "Invalid or replayed nonce"})
    if nonce_status == "expired":
        return JSONResponse(status_code=401, content={"detail": "Nonce has expired"})

    # 4. Key Confirmation Binding (Optional RFC 7800 cnf claim)
    bound_cred_id = payload.get("cnf", {}).get("kid")
    if bound_cred_id and not hmac.compare_digest(bound_cred_id, cred_id):
        return JSONResponse(status_code=401, content={"detail": "JWT is not bound to this key"})

    # 5. Claimed Body Digest Header Validation
    expected_digest = request.headers.get("X-Body-Digest")
    if not expected_digest or not expected_digest.startswith("sha256="):
        return JSONResponse(status_code=400, content={"detail": "Missing or invalid X-Body-Digest header"})
    expected_digest_val = expected_digest.split("=")[1]

    cred = get_credential(user_id, cred_id)
    if not cred:
        return JSONResponse(status_code=403, content={"detail": "Invalid FIDO2 PoP signature (credential not found)"})

    try:
        padding_needed = (4 - len(signature_b64) % 4) % 4
        signature = base64.urlsafe_b64decode(signature_b64 + "=" * padding_needed)
    except (binascii.Error, ValueError):
        return JSONResponse(status_code=403, content={"detail": "Invalid FIDO2 PoP signature (decode failed)"})

    canonical_payload = generate_canonical_payload(
        method=request.method,
        host=request.headers.get("Host", ""),
        path=request.url.path,
        query=request.url.query,
        body_hash=expected_digest_val,
        nonce=nonce,
        timestamp=timestamp,
    )

    # Offload CPU-bound ECDSA verification to worker thread pool to avoid blocking asyncio event loop
    is_valid = await to_thread.run_sync(
        verify_pop_signature,
        cred.public_key_pem.encode("utf-8"),
        signature,
        canonical_payload,
    )
    if not is_valid:
        return JSONResponse(status_code=403, content={"detail": "Invalid FIDO2 PoP signature"})

    # 6. Stream Request Body and Verify Claimed Digest (Constant-time check)
    # Executed after signature validation to prevent resource exhaustion from unauthenticated requests
    body_hasher = hashlib.sha256()
    spooled_body = tempfile.SpooledTemporaryFile(max_size=settings.spooled_body_max_size_bytes)

    try:
        async for chunk in request.stream():
            body_hasher.update(chunk)
            spooled_body.write(chunk)

        spooled_body.seek(0)
        body_hash = body_hasher.hexdigest()

        if not hmac.compare_digest(body_hash, expected_digest_val):
            spooled_body.close()
            return JSONResponse(status_code=400, content={"detail": "Body digest mismatch"})

        request.state.spooled_body = spooled_body
        return await call_next(request)
    except Exception:
        spooled_body.close()
        raise
