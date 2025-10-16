from pydantic import BaseModel


class DepartmentResponse(BaseModel):
    code: str
    name: str

    class Config:
        from_attributes = True
