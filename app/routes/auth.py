import uuid
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordRequestForm
from app.core.security import verify_password, create_access_token, get_password_hash
from app.schemas.fido2 import RegisterKeyRequest, RegisterKeyResponse, NonceResponse
from app.core.credential_store import add_credential

router = APIRouter(prefix="/auth", tags=["Auth"])

# Mock user database
MOCK_USERS = {
    "testuser": {
        "username": "testuser",
        "role": "admin",
        "hashed_password": get_password_hash("secret")
    }
}

@router.post("/token")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    user = MOCK_USERS.get(form_data.username)
    if not user:
        if form_data.password == "secret":
            user = {
                "username": form_data.username,
                "role": "user",
                "hashed_password": get_password_hash("secret")
            }
            MOCK_USERS[form_data.username] = user
        else:
            raise HTTPException(status_code=400, detail="Incorrect username or password")
            
    if not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    payload_data = {"sub": user["username"], "role": user.get("role")}
    
    # Optional PoP binding
    bound_cred_id = request.headers.get("X-FIDO2-Credential-ID")
    if bound_cred_id:
        payload_data["cnf"] = {"kid": bound_cred_id}

    access_token = create_access_token(data=payload_data)
    return {"access_token": access_token, "token_type": "bearer"}

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from fastapi.security import OAuth2PasswordBearer
from app.core.security import decode_token
import jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

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
    except (ValueError, TypeError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid public key PEM: {e}")
        
    try:
        add_credential(user, req.credential_id, req.public_key_pem)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
        
    return RegisterKeyResponse(status="success", message="FIDO2 key registered successfully")

from app.core.nonce_store import nonce_store

@router.get("/nonce", response_model=NonceResponse)
async def get_nonce():
    return NonceResponse(nonce=nonce_store.issue_nonce())
