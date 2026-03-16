from openg2p_fastapi_common.config import Settings as BaseSettings
from pydantic_settings import SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="common_", env_file=".env", extra="allow", env_nested_delimiter="__"
    )

    login_providers_table_enabled: bool = True
    login_providers_table_name: str = "login_providers"

    keymanager_sign_app_id: str = ""
