from pydantic import BaseModel

class RegisterKeyRequest(BaseModel):
    credential_id: str
    public_key_pem: str

class RegisterKeyResponse(BaseModel):
    status: str
    message: str

class NonceResponse(BaseModel):
    nonce: str
