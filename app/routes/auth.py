import hmac
from typing import Dict

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt

from app.core.credential_store import add_credential
from app.core.nonce_store import nonce_store
from app.core.security import create_access_token, decode_token, get_password_hash, verify_password
from app.schemas.fido2 import NonceResponse, RegisterKeyRequest, RegisterKeyResponse

router = APIRouter(prefix="/auth", tags=["Auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# Mock user database for demonstration and testing
MOCK_USERS: Dict[str, dict] = {
    "testuser": {
        "username": "testuser",
        "role": "admin",
        "hashed_password": get_password_hash("secret"),
    }
}


@router.post("/token")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    user = MOCK_USERS.get(form_data.username)
    if not user:
        # Dynamically provision mock user for benchmark/testing users (e.g., locust_user_*)
        if hmac.compare_digest(form_data.password, "secret"):
            user = {
                "username": form_data.username,
                "role": "user",
                "hashed_password": get_password_hash("secret"),
            }
            MOCK_USERS[form_data.username] = user
        else:
            raise HTTPException(status_code=400, detail="Incorrect username or password")

    if not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    payload_data = {"sub": user["username"], "role": user.get("role")}

    # Optional key confirmation binding (RFC 7800 / DPoP style confirmation)
    bound_cred_id = request.headers.get("X-FIDO2-Credential-ID")
    if bound_cred_id:
        payload_data["cnf"] = {"kid": bound_cred_id}

    access_token = create_access_token(data=payload_data)
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/register-key", response_model=RegisterKeyResponse)
async def register_key(req: RegisterKeyRequest, token: str = Depends(oauth2_scheme)):
    try:
        payload = decode_token(token)
        user = payload.get("sub")
    except (jwt.PyJWTError, jwt.ExpiredSignatureError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if not user:
        raise HTTPException(status_code=401, detail="Authentication required to register key")

    try:
        load_pem_public_key(req.public_key_pem.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid public key PEM: {exc}")

    try:
        add_credential(user, req.credential_id, req.public_key_pem)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return RegisterKeyResponse(status="success", message="FIDO2 key registered successfully")


@router.get("/nonce", response_model=NonceResponse)
async def get_nonce():
    return NonceResponse(nonce=nonce_store.issue_nonce())
