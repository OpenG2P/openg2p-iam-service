from datetime import datetime, timezone

from openg2p_fastapi_common.config import Settings as BaseSettings
from pydantic import model_validator
from pydantic_settings import SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="common_", env_file=".env", extra="allow", env_nested_delimiter="__"
    )

    login_providers_table_enabled: bool = True
    login_providers_table_name: str = "login_providers"
    login_providers_list: list[dict] = []

    keymanager_sign_app_id: str = ""

    @model_validator(mode="after")
    def validate_login_providers_list(self):
        if self.login_providers_list:
            self.login_providers_list.sort(key=lambda x: x.get("id"))

            for lp in self.login_providers_list:
                if not lp.get("created_at"):
                    lp["created_at"] = datetime.now(timezone.utc).replace(tzinfo=None)

        return self
