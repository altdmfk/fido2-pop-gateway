from typing import Dict, List, Optional
from pydantic import BaseModel

class CredentialRecord(BaseModel):
    credential_id: str
    public_key_pem: str

# Mock storage linking username to a list of credentials
MOCK_CREDENTIAL_STORE: Dict[str, List[CredentialRecord]] = {}

def add_credential(username: str, credential_id: str, public_key_pem: str) -> None:
    if username not in MOCK_CREDENTIAL_STORE:
        MOCK_CREDENTIAL_STORE[username] = []
    MOCK_CREDENTIAL_STORE[username].append(CredentialRecord(
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
