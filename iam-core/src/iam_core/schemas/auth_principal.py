from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AuthPrincipal(BaseModel):
    model_config = ConfigDict(extra="allow")

    scheme: str = "bearer"
    credentials: str
    iss: str | None = None
    sub: str | None = None
    user_type: str | None = None
    aud: str | list | None = None
    iat: datetime | None = None
    exp: datetime | None = None
    roles: list[str] = Field(default_factory=list)
    client_roles: dict[str, list[str]] | None = None
    provider: str | None = None
    raw_claims: dict[str, Any] = Field(default_factory=dict)
