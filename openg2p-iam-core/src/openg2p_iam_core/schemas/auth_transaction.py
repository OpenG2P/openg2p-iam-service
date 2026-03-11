from datetime import datetime

from pydantic import BaseModel


class AuthTransaction(BaseModel):
    state: str
    code_verifier: str
    nonce: str
    login_provider_id: int
    redirect_uri: str
    created_at: datetime
    expires_at: datetime
