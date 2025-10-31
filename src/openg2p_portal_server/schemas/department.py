from pydantic import BaseModel


class DepartmentResponse(BaseModel):
    department_name: str
    department_mnemonic: str
    base_url: str
    bridge_relative_url: str
    spar_relative_url: str
    pbms_relative_url: str
    registry_relative_url: str
    superset_relative_url: str

    class Config:
        from_attributes = True
