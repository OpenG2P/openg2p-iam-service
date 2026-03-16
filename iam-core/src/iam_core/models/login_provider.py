import json
import sys
from enum import Enum

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from typing import Optional

from openg2p_fastapi_common.models import BaseORMModelWithTimes
from sqlalchemy import Boolean, Enum as SAEnum, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from ..schemas import TokenEndpointAuthMethod


class UserTypeEnum(str, Enum):
    staff = "staff"
    agent = "agent"
    beneficiary = "beneficiary"


class LoginProvider(BaseORMModelWithTimes):
    __tablename__ = "login_providers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_type: Mapped[UserTypeEnum] = mapped_column(SAEnum(UserTypeEnum), nullable=False)
    provider_name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    icon_base64: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    client_id: Mapped[str] = mapped_column(String, nullable=False)
    client_secret: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    token_endpoint_auth_method: Mapped[TokenEndpointAuthMethod] = mapped_column(
        SAEnum(TokenEndpointAuthMethod), nullable=False
    )
    keymanager_app_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    keymanager_ref_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    authorization_endpoint: Mapped[Optional[str]] = mapped_column(String, nullable=True) #IdP URL
    userinfo_endpoint: Mapped[Optional[str]] = mapped_column(String, nullable=True) # Optional URL to fetch user info from IdP.
    token_endpoint: Mapped[Optional[str]] = mapped_column(String, nullable=True) # Optional URL to fetch token from IdP.
    server_metadata_url: Mapped[Optional[str]] = mapped_column(String, nullable=True) # Optional URL to fetch OIDC server metadata from IdP, can be used as an alternative to manually specifying authorization_endpoint, token_endpoint and jwks_uri.
    adapter_name: Mapped[Optional[str]] = mapped_column(String, nullable=True) 
    jwks_uri: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    jwt_assertion_aud: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    scope: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    enable_pkce: Mapped[Optional[bool]] = mapped_column(Boolean(), nullable=True)
    extra_authorize_params: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    issuer: Mapped[str] = mapped_column(String, nullable=False)  # Canonical OIDC issuer URL
    audiences: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # JSON-encoded list of allowed audiences
    oauth_callback_url: Mapped[str] = mapped_column(String, nullable=False) # The callback URL registered with the IdP for this login provider, used in the OIDC authorization flow. This is required to be stored for each login provider as different providers may have different callback URLs registered with the IdP.
    default_redirect_uri: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # Optional default redirect URI after login; used when the client does not send one.

    @property
    def audiences_list(self) -> list[str]:
        if not self.audiences:
            return []
        return json.loads(self.audiences)

    @classmethod
    async def get_login_provider_from_iss(cls, iss: str) -> Self:
        providers = await cls.get_all()
        for lp in providers:
            if lp.issuer == iss:
                return lp
        return None

    @classmethod
    async def get_by_user_type(cls, user_type: str) -> list[Self]:
        normalized = user_type.lower()
        providers = await cls.get_all()
        return [provider for provider in providers if provider.user_type.value == normalized]
