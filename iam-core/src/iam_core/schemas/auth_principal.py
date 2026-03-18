from pydantic import BaseModel, ConfigDict


class AuthPrincipal(BaseModel):
    model_config = ConfigDict(extra="allow")

    scheme: str = "bearer"
    credentials: str
    sub: str | None = None
    user_type: str | None = None
    aud: str | list | None = None
    client_roles: dict[str, list[str]] | None = None
