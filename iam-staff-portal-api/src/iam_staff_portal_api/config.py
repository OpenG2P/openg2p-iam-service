from iam_core.user_auth.config import Settings as BaseSettings
from iam_core.user_auth.config import ApiAuthSettings

from pydantic import Field
from pydantic_settings import SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="iam_staff_",
        env_file=".env",
        extra="allow",
        env_nested_delimiter="__",
    )
    auth_api_get_staff_portal_applications: ApiAuthSettings = ApiAuthSettings(enabled=True)
    data_application_urls: dict[str, str] = Field(
        default_factory=lambda: {
            "keycloak_application_url": "https://keycloak.openg2p.org",
            "registry_application_url": "https://registry.openg2p.org",
            "minio_application_url": "https://minio.openg2p.org",
        }
    )
    data_client_secrets: dict[str, str] = Field(default_factory=dict)
    cache_expire_seconds: int = 7*24*60*60      # 7 days
    data_dir: str = "/opt/iam-staff-portal-data"
