from datetime import date
from typing import Optional, List
from pydantic import BaseModel, ConfigDict


class DepartmentResponse(BaseModel):
    code: str
    name: str
    
    class Config:
        from_attributes = True


class UserBase(BaseModel):
    model_config = ConfigDict()

    name: str
    provider_unique_id: str
    provider_unique_id_type: str
    email: Optional[str] = None
    gender: Optional[str] = None
    birthdate: Optional[date] = None
    phone_number: Optional[str] = None
    user_type: Optional[str] = None


class UserData(UserBase):
    auth_provider_id: Optional[int] = None
    user_id: Optional[str] = None


class UserResponse(UserBase):
    id: int
    departments: List[DepartmentResponse] = []
    
    class Config:
        from_attributes = True
