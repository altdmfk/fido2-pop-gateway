from typing import Dict, List, Optional
from pydantic import BaseModel

class CredentialRecord(BaseModel):
    credential_id: str
    public_key_pem: str

# Mock storage linking username to a list of credentials
MOCK_CREDENTIAL_STORE: Dict[str, List[CredentialRecord]] = {}

MAX_CREDENTIALS_PER_USER = 20

def add_credential(username: str, credential_id: str, public_key_pem: str) -> None:
    creds = MOCK_CREDENTIAL_STORE.setdefault(username, [])
    
    for c in creds:
        if c.credential_id == credential_id:
            raise ValueError("Credential ID already registered")
            
    if len(creds) >= MAX_CREDENTIALS_PER_USER:
        raise ValueError("Maximum credentials per user exceeded")
        
    creds.append(CredentialRecord(
        credential_id=credential_id,
        public_key_pem=public_key_pem
    ))

def get_credentials(username: str) -> List[CredentialRecord]:
    return MOCK_CREDENTIAL_STORE.get(username, [])

def get_credential(username: str, credential_id: str) -> Optional[CredentialRecord]:
    records = get_credentials(username)
    for r in records:
        if r.credential_id == credential_id:
            return r
    return None
