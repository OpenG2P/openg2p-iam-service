from typing import Any, ABC

from openg2p_iam_core.models import LoginProvider


class OIDCInterface(ABC):
    async def build_authorize_redirect(
        self,
        login_provider: LoginProvider,
        state: str,
        nonce: str,
        code_verifier: str,
        server_metadata: dict | None = None,
    ) -> tuple[str, str]:
        ...

    async def exchange_code_for_token(
        self,
        login_provider: LoginProvider,
        code: str | None,
        code_verifier: str | None = None,
        keymanager_helper=None,
        server_metadata: dict | None = None,
        **kw,
    ) -> dict[str, Any]:
        ...

    async def validate_callback_id_token(
        self,
        login_provider: LoginProvider,
        token_response: dict[str, Any],
        nonce: str | None,
        server_metadata: dict | None = None,
    ) -> None:
        ...

    async def get_oauth_validation_data(
        self,
        login_provider: LoginProvider,
        access_token: str,
    ) -> dict[str, Any]:
        ...

    async def decode_access_token(
        self,
        login_provider: LoginProvider,
        jwt_token: str,
        iss: str | None = None,
    ) -> dict[str, Any]:
        ...

    async def decode_id_token(
        self,
        login_provider: LoginProvider,
        jwt_id_token: str,
        jwt_token: str,
        iss: str | None = None,
    ) -> dict[str, Any]:
        ...

    async def introspect_token(
        self,
        login_provider: LoginProvider,
        jwt_token: str,
        endpoint: str | None = None,
    ) -> dict[str, Any]:
        ...

    def normalize_claims(
        self,
        claims: dict[str, Any],
        login_provider: LoginProvider,
    ) -> dict[str, Any]:
        ...

    def validate_claims(
        self,
        claims: dict[str, Any],
        login_provider: LoginProvider,
    ) -> None:
        ...
