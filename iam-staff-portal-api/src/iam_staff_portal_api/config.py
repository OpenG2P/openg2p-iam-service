from iam_core.user_auth.config import Settings as BaseSettings
from iam_core.user_auth.config import ApiAuthSettings

from pydantic_settings import SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="iam_staff_",
        env_file=".env",
        extra="allow",
        env_nested_delimiter="__",
    )
    auth_api_get_staff_portal_applications: ApiAuthSettings = ApiAuthSettings(enabled=True)