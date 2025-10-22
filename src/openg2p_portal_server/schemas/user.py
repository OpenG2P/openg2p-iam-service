from typing import Optional
from datetime import date
from pydantic import BaseModel


class UserProfile(BaseModel):
    name: str | None = None
    picture: str | None = None
    email: str | None = None
    gender: str | None = None
    birthdate: date | None = None
    phone_number: str | None = None
    user_type: Optional[str] = None
    login_provider_id: Optional[int] = None
    user_id: Optional[str] = None
    provider_unique_id: str
    provider_unique_id_type: str
