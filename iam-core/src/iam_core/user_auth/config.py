from typing import Literal

from openg2p_fastapi_common.config import Settings as BaseSettings
from pydantic import BaseModel
from pydantic_settings import SettingsConfigDict

from .. import __version__


class ApiAuthSettings(BaseModel):
    enabled: bool = False
    claim_name: str | None = None
    claim_values: list[str] | None = None
    id_token_verify_at_hash: bool | None = None
    validation_mode: Literal["jwt", "introspection", "hybrid"] = "jwt"
    introspection_endpoint: str | None = None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="common_", env_file=".env", extra="allow", env_nested_delimiter="__"
    )

    openapi_title: str = "OpenG2P IAM Service"
    openapi_version: str = __version__

    auth_enabled: bool = True

    auth_cookie_max_age: int | None = None
    auth_cookie_set_expires: bool = False
    auth_cookie_domain: str | None = None
    auth_cookie_path: str = "/"
    auth_cookie_httponly: bool = True
    auth_cookie_secure: bool = True

    auth_transaction_store_backend: Literal["memory", "redis"] = "memory"
    auth_redis_url: str = "redis://localhost:6379/0"

    auth_default_id_token_verify_at_hash: bool = True

    auth_api_get_user_profile: ApiAuthSettings = ApiAuthSettings(enabled=True)
