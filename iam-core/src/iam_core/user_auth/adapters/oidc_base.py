from typing import Any

from openg2p_fastapi_common.service import BaseService

from iam_core.models import LoginProvider
from iam_core.user_auth.oidc_client import OidcClient
from .oidc_interface import OIDCInterface


class OIDCBase(BaseService, OIDCInterface):
    def __init__(self, oidc_client: OidcClient | None = None):
        super().__init__()
        self.oidc_client = oidc_client or OidcClient()

    async def build_authorize_redirect(
        self,
        login_provider: LoginProvider,
        state: str,
        nonce: str,
        code_verifier: str,
        server_metadata: dict | None = None,
    ) -> tuple[str, str]:
        return await self.oidc_client.build_authorize_redirect(
            login_provider=login_provider,
            state=state,
            nonce=nonce,
            code_verifier=code_verifier,
            server_metadata=server_metadata,
        )

    async def exchange_code_for_token(
        self,
        login_provider: LoginProvider,
        code: str | None,
        code_verifier: str | None = None,
        keymanager_helper=None,
        server_metadata: dict | None = None,
        **kw,
    ) -> dict[str, Any]:
        return await self.oidc_client.exchange_code_for_token(
            login_provider=login_provider,
            code=code,
            code_verifier=code_verifier,
            keymanager_helper=keymanager_helper,
            server_metadata=server_metadata,
            **kw,
        )

    async def validate_callback_id_token(
        self,
        login_provider: LoginProvider,
        token_response: dict[str, Any],
        nonce: str | None,
        server_metadata: dict | None = None,
    ) -> None:
        id_token = token_response.get("id_token")
        if not id_token:
            return
        await self.oidc_client.decode_jwt(
            login_provider=login_provider,
            token=id_token,
            nonce=nonce,
            access_token=token_response.get("access_token"),
            server_metadata=server_metadata,
        )

    async def get_oauth_validation_data(
        self,
        login_provider: LoginProvider,
        access_token: str,
    ) -> dict[str, Any]:
        return await self.oidc_client.get_oauth_validation_data(
            login_provider=login_provider,
            access_token=access_token,
        )

    async def decode_access_token(
        self,
        login_provider: LoginProvider,
        jwt_token: str,
        iss: str | None = None,
    ) -> dict[str, Any]:
        return await self.oidc_client.decode_jwt(
            login_provider=login_provider,
            token=jwt_token,
            verify_exp=True,
            iss=iss,
        )

    async def decode_id_token(
        self,
        login_provider: LoginProvider,
        jwt_id_token: str,
        jwt_token: str,
        iss: str | None = None,
    ) -> dict[str, Any]:
        return await self.oidc_client.decode_jwt(
            login_provider=login_provider,
            token=jwt_id_token,
            verify_exp=True,
            access_token=jwt_token,
            iss=iss,
        )

    async def introspect_token(
        self,
        login_provider: LoginProvider,
        jwt_token: str,
        endpoint: str | None = None,
    ) -> dict[str, Any]:
        return await self.oidc_client.introspect_token(
            login_provider=login_provider,
            token=jwt_token,
            endpoint=endpoint,
        )

    def normalize_claims(
        self,
        claims: dict[str, Any],
        login_provider: LoginProvider,
    ) -> dict[str, Any]:
        # Default path: preserve claims as-is.
        return claims

    def validate_claims(
        self,
        claims: dict[str, Any],
        login_provider: LoginProvider,
    ) -> None:
        # Default path: no provider-specific validation.
        return None
