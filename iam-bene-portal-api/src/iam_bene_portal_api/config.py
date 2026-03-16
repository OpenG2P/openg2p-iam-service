from iam_core.user_auth.config import Settings as BaseSettings
from pydantic_settings import SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="iam_bene_",
        env_file=".env",
        extra="allow",
        env_nested_delimiter="__",
    )
