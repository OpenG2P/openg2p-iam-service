from pydantic import BaseModel


class DepartmentResponse(BaseModel):
    department_name: str
    department_mnemonic: str
    bridge_url: str
    spar_url: str
    pbms_url: str
    registry_url: str
    superset_url: str

    class Config:
        from_attributes = True
