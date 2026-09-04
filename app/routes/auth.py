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
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = MOCK_USERS.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": user["username"], "role": user.get("role")})
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/register-key", response_model=RegisterKeyResponse)
async def register_key(req: RegisterKeyRequest, request: Request):
    user = getattr(request.state, "user", "testuser")
    add_credential(user, req.credential_id, req.public_key_pem)
    return RegisterKeyResponse(status="success", message="FIDO2 key registered successfully")

from app.core.nonce_store import nonce_store

@router.get("/nonce", response_model=NonceResponse)
async def get_nonce():
    return NonceResponse(nonce=nonce_store.issue_nonce())
