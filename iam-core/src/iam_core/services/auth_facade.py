import orjson
from jose import jwt as jose_jwt
from openg2p_fastapi_common.errors.http_exceptions import UnauthorizedError

from openg2p_iam_core.schemas import (
    LoginProviderHttpResponse,
    LoginProviderResponse,
    StartAuthTransactionResponse,
)
from openg2p_iam_core.services.auth_transaction_store import auth_transaction_store
from openg2p_iam_core.services.provider_repository import ProviderRepository
from openg2p_iam_core.user_auth.oidc_service import AuthlibOidcService


class AuthFacade:
    def __init__(self, user_type: str | None = None):
        self.user_type = user_type
        self._providers = ProviderRepository()
        self._oidc = AuthlibOidcService()

    async def get_login_providers(self) -> LoginProviderHttpResponse:
        login_providers = await self._providers.get_all(user_type=self.user_type)
        return LoginProviderHttpResponse(
            loginProviders=[
                LoginProviderResponse(
                    id=lp.id,
                    name=lp.provider_name,
                    displayName=lp.description or lp.provider_name,
                    displayIconUrl=lp.icon_base64 or "",
                )
                for lp in login_providers
            ],
        )

    async def start_login(
        self,
        provider_id: int,
        redirect_uri: str = "/",
    ) -> StartAuthTransactionResponse:
        login_provider = await self._providers.get_by_id(provider_id)
        if not login_provider:
            raise UnauthorizedError("G2P-AUT-401", "Invalid Login Provider Id")

        txn = auth_transaction_store.create(
            login_provider_id=login_provider.id,
            redirect_uri=redirect_uri,
        )
        redirect_url, state = await self._oidc.build_authorize_redirect(
            login_provider,
            state=txn.state,
            nonce=txn.nonce,
            code_verifier=txn.code_verifier,
        )
        return StartAuthTransactionResponse(redirectUrl=redirect_url, state=state)

    async def complete_login(
        self,
        state_value: str | None,
        code: str | None,
        keymanager_helper=None,
        **kw,
    ) -> dict:
        txn = auth_transaction_store.get_and_pop(state_value)
        if txn:
            login_provider = await self._providers.get_by_id(txn.login_provider_id)
            if not login_provider:
                raise UnauthorizedError("G2P-AUT-401", "Invalid Login Provider Id")

            token_response = await self._oidc.exchange_code_for_token(
                login_provider=login_provider,
                code=code,
                code_verifier=txn.code_verifier,
                keymanager_helper=keymanager_helper,
                **kw,
            )
            id_token = token_response.get("id_token")
            if id_token:
                await self._oidc.decode_jwt(
                    login_provider,
                    id_token,
                    nonce=txn.nonce,
                    access_token=token_response.get("access_token"),
                )
            return {
                "redirect_uri": txn.redirect_uri,
                "token_response": token_response,
            }

        # Legacy fallback state format support.
        state = orjson.loads(state_value or "{}")
        login_provider_id = state.get("p")
        if not login_provider_id:
            raise UnauthorizedError("G2P-AUT-401", "Login Provider Id not received")
        login_provider = await self._providers.get_by_id(login_provider_id)
        if not login_provider:
            raise UnauthorizedError("G2P-AUT-401", "Invalid Login Provider Id")

        token_response = await self._oidc.exchange_code_for_token(
            login_provider=login_provider,
            code=code,
            code_verifier=None,
            keymanager_helper=keymanager_helper,
            **kw,
        )
        return {
            "redirect_uri": state.get("r", "/"),
            "token_response": token_response,
        }

    async def get_oauth_validation_data(
        self,
        auth: str,
        id_token: str | None = None,
        iss: str | None = None,
        combine: bool = True,
    ) -> dict:
        access_token = auth
        issuer = iss or jose_jwt.get_unverified_claims(access_token).get("iss")
        login_provider = await self._providers.get_by_iss(issuer)
        if not login_provider:
            raise UnauthorizedError(message=f"Unauthorized. Unknown Issuer. {issuer}")

        userinfo = await self._oidc.get_oauth_validation_data(
            login_provider=login_provider,
            access_token=access_token,
        )
        if not combine:
            return userinfo
        return self.combine_tokens(access_token, id_token, userinfo)

    @classmethod
    def combine_token_dicts(cls, *token_dicts) -> dict:
        response = None
        for token_dict in token_dicts:
            if token_dict:
                if not response:
                    response = token_dict
                else:
                    for key, value in token_dict.items():
                        if value:
                            response[key] = value
        return response or {}

    @classmethod
    def combine_tokens(cls, *tokens) -> dict:
        values = []
        for token in tokens:
            if token:
                try:
                    values.append(
                        jose_jwt.get_unverified_claims(token)
                        if isinstance(token, str)
                        else token
                    )
                except Exception:
                    pass
        return cls.combine_token_dicts(*values)
