from datetime import datetime, timezone

from openg2p_iam_core.user_auth.config import Settings as BaseSettings
from pydantic import model_validator
from pydantic_settings import SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="iam_bene_", env_file=".env", extra="allow", env_nested_delimiter="__"
    )

    @model_validator(mode="after")
    def validate_login_providers_list(self):
        if self.login_providers_list:
            code_verifier = self.login_providers_list_pkce_code_verifier
            self.login_providers_list.sort(key=lambda x: x.get("id"))

            from openg2p_iam_core.schemas import LoginProviderTypes

            for lp in self.login_providers_list:
                if "type" in lp:
                    lp["type"] = LoginProviderTypes[lp["type"]]

                lp_auth_params = lp.get("authorization_parameters")
                if code_verifier and lp_auth_params:
                    lp_auth_params["code_verifier"] = code_verifier
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
