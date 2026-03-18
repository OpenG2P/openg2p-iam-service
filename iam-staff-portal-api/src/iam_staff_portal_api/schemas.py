from typing import List, Optional
from pydantic import BaseModel


class StaffPortalApplicationResponse(BaseModel):
    id: int
    application_mnemonic: str
    application_description: Optional[str] = None
    application_url: Optional[str] = None
    icon_base64: Optional[str] = None
    width: Optional[int] = None
    application_url: Optional[str] = None
    order: Optional[int] = None
    disabled: bool


class ApplicationActionResponse(BaseModel):
    application_id: int
    application_mnemonic: str
    actions: List[str]
