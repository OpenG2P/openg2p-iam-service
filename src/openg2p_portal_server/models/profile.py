from datetime import date
from typing import Optional

from pydantic import BaseModel, ConfigDict


class Profile(BaseModel):
    model_config = ConfigDict()

    name: str
    individual_id: str
    email: Optional[str] = None
    gender: Optional[str] = None
    birthdate: Optional[date] = None
    phone_number: Optional[str] = None
    address: Optional[dict] = None
    user_type: Optional[str] = None


class GetProfile(Profile):
    id: Optional[int] = None
