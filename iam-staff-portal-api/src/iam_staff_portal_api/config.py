from datetime import datetime, timezone

from iam_core.user_auth.config import Settings as BaseSettings
from pydantic import model_validator
from pydantic_settings import SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="iam_staff_",
        env_file=".env",
        extra="allow",
        env_nested_delimiter="__",
    )

    @model_validator(mode="after")
    def validate_login_providers_list(self):
        if self.login_providers_list:
            self.login_providers_list.sort(key=lambda x: x.get("id"))

            for lp in self.login_providers_list:
                if not lp.get("created_at"):
                    lp["created_at"] = datetime.now(timezone.utc).replace(tzinfo=None)

            if not self.auth_default_issuers:
                self.auth_default_issuers = [
                    lp.get("iss") for lp in self.login_providers_list
                ]
            if not self.auth_default_jwks_urls:
                self.auth_default_jwks_urls = [
                    lp.get("jwks_url") for lp in self.login_providers_list
                ]
        return self
