import hmac
import threading
from typing import Dict, List, Optional
from pydantic import BaseModel

from app.core.config import settings


class CredentialRecord(BaseModel):
    credential_id: str
    public_key_pem: str


# In-memory storage mapping username to authorized FIDO2 credential records
_store_lock = threading.Lock()
MOCK_CREDENTIAL_STORE: Dict[str, List[CredentialRecord]] = {}


def add_credential(username: str, credential_id: str, public_key_pem: str) -> None:
    with _store_lock:
        creds = MOCK_CREDENTIAL_STORE.setdefault(username, [])

        for c in creds:
            if hmac.compare_digest(c.credential_id, credential_id):
                raise ValueError("Credential ID already registered")

        if len(creds) >= settings.max_credentials_per_user:
            raise ValueError("Maximum credentials per user exceeded")

        creds.append(CredentialRecord(
            credential_id=credential_id,
            public_key_pem=public_key_pem,
        ))


def get_credentials(username: str) -> List[CredentialRecord]:
    with _store_lock:
        return list(MOCK_CREDENTIAL_STORE.get(username, []))


def get_credential(username: str, credential_id: str) -> Optional[CredentialRecord]:
    for r in get_credentials(username):
        if hmac.compare_digest(r.credential_id, credential_id):
            return r
    return None
