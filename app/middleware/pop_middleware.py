import time
import base64
from fastapi import Request
from fastapi.responses import JSONResponse
import jwt
from app.core.security import decode_token
from app.core.nonce_store import nonce_store
from app.core.credential_store import get_credential
from app.core.crypto import verify_pop_signature, generate_canonical_payload

async def pop_middleware(request: Request, call_next):
    if not request.url.path.startswith("/api/"):
        return await call_next(request)

    # Step A (JWT Check)
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

    if request.url.path == "/api/v1/baseline-jwt":
        response = await call_next(request)
        return response

    # Step B (Header Extraction)
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

    # Step C (Freshness & Replay Check)
    current_time = int(time.time())
    if abs(current_time - timestamp) > 60:
        return JSONResponse(status_code=401, content={"detail": "Timestamp expired"})

    if not nonce_store.consume_nonce(nonce):
        return JSONResponse(status_code=401, content={"detail": "Invalid or replayed nonce"})

    # Step D (Cryptographic Verification)
    cred = get_credential(user_id, cred_id)
    if not cred:
        return JSONResponse(status_code=403, content={"detail": "Invalid FIDO2 PoP signature"})

    try:
        signature = base64.urlsafe_b64decode(signature_b64 + "===")
    except Exception:
        return JSONResponse(status_code=403, content={"detail": "Invalid FIDO2 PoP signature"})

    body = await request.body()
    
    canonical_payload = generate_canonical_payload(
        method=request.method,
        path=request.url.path,
        body=body,
        nonce=nonce,
        timestamp=timestamp
    )

    if not verify_pop_signature(cred.public_key_pem.encode("utf-8"), signature, canonical_payload):
        return JSONResponse(status_code=403, content={"detail": "Invalid FIDO2 PoP signature"})

    # Step E (Forwarding)
    response = await call_next(request)
    return response
