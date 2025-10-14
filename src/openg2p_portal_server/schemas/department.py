from datetime import date
from typing import Optional
from pydantic import BaseModel, ConfigDict


class DepartmentResponse(BaseModel):
    code: str
    name: str

    class Config:
        from_attributes = True