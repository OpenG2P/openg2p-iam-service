from datetime import date
from typing import Optional

from pydantic import BaseModel, ConfigDict


class UserProfile(BaseModel):
    model_config = ConfigDict()

    name: str
    user_unique_id: str
    id_type: str
    email: Optional[str] = None
    gender: Optional[str] = None
    birthdate: Optional[date] = None
    phone_number: Optional[str] = None
    user_type: Optional[str] = None


class GetUserProfile(UserProfile):
    id: Optional[int] = None
