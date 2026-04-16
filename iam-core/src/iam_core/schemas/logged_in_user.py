from typing import Any

from pydantic import BaseModel, Field


class LoggedInUserResponse(BaseModel):
    sub: str | None = None
    email_verified: bool | None = None
    address: dict[str, Any] = Field(default_factory=dict)
    name: str | None = None
    preferred_username: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    email: str | None = None
