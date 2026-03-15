import json
import logging
from urllib.parse import urlparse

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from jose import jwt as jose_jwt
from openg2p_fastapi_common.errors.http_exceptions import InternalServerError, UnauthorizedError

from openg2p_iam_core.context import server_metadata_cache
from openg2p_iam_core.models import LoginProvider
from openg2p_iam_core.schemas import TokenEndpointAuthMethod

from .config import Settings
from .helpers import decode_jwt as jwt_decode
from .helpers import generate_client_assertion
from .helpers import get_jwks as jwks_get
from .helpers import pkce_kwargs

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class OidcClient:
    @staticmethod
    def _extra_params(login_provider: LoginProvider) -> dict:
        if not login_provider.extra_authorize_params:
            return {}
        try:
            return json.loads(login_provider.extra_authorize_params)
        except Exception:
            return {}

    @classmethod
    def _guess_issuer(cls, login_provider: LoginProvider) -> str | None:
        extra = cls._extra_params(login_provider)
        issuer = extra.get("issuer")
        if issuer:
            return issuer.rstrip("/")

        for endpoint in (
            login_provider.token_endpoint,
            login_provider.authorization_endpoint,
            login_provider.userinfo_endpoint,
        ):
            if not endpoint:
                continue
            parsed = urlparse(endpoint)
            if parsed.scheme and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}"
        return None

    @classmethod
    def _metadata_url(cls, login_provider: LoginProvider) -> str | None:
        metadata_url = login_provider.server_metadata_url
        if metadata_url:
            return metadata_url

        extra = cls._extra_params(login_provider)
        metadata_url = extra.get("server_metadata_url")
        if metadata_url:
            return metadata_url

        issuer = cls._guess_issuer(login_provider)
        if not issuer:
            return None
        return f"{issuer.rstrip('/')}/.well-known/openid-configuration"

    async def get_server_metadata(self, login_provider: LoginProvider) -> dict:
        cache = server_metadata_cache.get() or {}
        cache_key = f"lp:{login_provider.id}"
        if cache_key in cache:
            return cache[cache_key]

        metadata_url = self._metadata_url(login_provider)
        metadata = {}
        if metadata_url:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(metadata_url)
                response.raise_for_status()
                metadata = response.json()

        if login_provider.authorization_endpoint:
            metadata["authorization_endpoint"] = login_provider.authorization_endpoint
        if login_provider.token_endpoint:
            metadata["token_endpoint"] = login_provider.token_endpoint
        if login_provider.userinfo_endpoint:
            metadata["userinfo_endpoint"] = login_provider.userinfo_endpoint
        if login_provider.jwks_uri:
            metadata["jwks_uri"] = login_provider.jwks_uri

        cache[cache_key] = metadata
        server_metadata_cache.set(cache)
        return metadata

    async def build_authorize_redirect(
        self,
        login_provider: LoginProvider,
        state: str,
        nonce: str,
        code_verifier: str,
        server_metadata: dict | None = None,
    ) -> tuple[str, str]:
        metadata = (
            server_metadata
            if server_metadata is not None
            else await self.get_server_metadata(login_provider)
        )
        auth_endpoint = metadata.get("authorization_endpoint")
        if not auth_endpoint:
            raise InternalServerError("G2P-AUT-500", "authorization_endpoint missing.")

        extra_authorize_params = self._extra_params(login_provider)
        async_oauth2_client: AsyncOAuth2Client = AsyncOAuth2Client(
            client_id=login_provider.client_id
        )
        params = {
            "redirect_uri": login_provider.oauth_callback_url,
            "scope": login_provider.scope or "openid profile email",
            "state": state,
            "nonce": nonce,
            "response_type": "code",
        }
        if login_provider.enable_pkce:
            params["code_verifier"] = code_verifier
            params["code_challenge_method"] = "S256"
        params.update(extra_authorize_params)
        return async_oauth2_client.create_authorization_url(auth_endpoint, **params)

    async def exchange_code_for_token(
        self,
        login_provider: LoginProvider,
        code: str,
        code_verifier: str | None = None,
        keymanager_helper=None,
        server_metadata: dict | None = None,
        **kw,
    ) -> dict:
        metadata = (
            server_metadata
            if server_metadata is not None
            else await self.get_server_metadata(login_provider)
        )
        token_endpoint = metadata.get("token_endpoint")
        if not token_endpoint:
            raise UnauthorizedError(message="Unauthorized. Missing token endpoint.")

        client_kwargs = {}
        token_kwargs = {
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": login_provider.oauth_callback_url,
        }
        token_kwargs.update(pkce_kwargs(login_provider, code_verifier))

        method = login_provider.token_endpoint_auth_method
        if method == TokenEndpointAuthMethod.client_secret_basic:
            client_kwargs["client_secret"] = login_provider.client_secret
            client_kwargs["token_endpoint_auth_method"] = method.value
        elif method == TokenEndpointAuthMethod.client_secret_post:
            client_kwargs["client_secret"] = login_provider.client_secret
            client_kwargs["token_endpoint_auth_method"] = method.value
        elif method == TokenEndpointAuthMethod.private_key_jwt_keymanager:
            client_kwargs["token_endpoint_auth_method"] = method.value
            keymanager_assertion_type, keymanager_token = await generate_client_assertion(
                login_provider,
                keymanager_helper=keymanager_helper,
                **kw,
            )
            token_kwargs["client_assertion_type"] = keymanager_assertion_type
            token_kwargs["client_assertion"] = keymanager_token

        client = AsyncOAuth2Client(
            client_id=login_provider.client_id,
            **client_kwargs,
        )
        idp_token = await client.fetch_token(token_endpoint, **token_kwargs)
        return dict(idp_token)

    async def decode_jwt(
        self,
        login_provider: LoginProvider,
        token: str,
        verify_exp: bool = True,
        nonce: str | None = None,
        access_token: str | None = None,
        iss: str | None = None,
        server_metadata: dict | None = None,
    ) -> dict:
        metadata = (
            server_metadata
            if server_metadata is not None
            else await self.get_server_metadata(login_provider)
        )
        issuer = iss or metadata.get("issuer") or self._guess_issuer(login_provider)
        jwks = await jwks_get(metadata, issuer)
        return jwt_decode(
            token,
            jwks,
            verify_exp=verify_exp,
            nonce=nonce,
            access_token=access_token,
        )

    async def get_oauth_validation_data(
        self,
        login_provider: LoginProvider,
        access_token: str,
        server_metadata: dict | None = None,
    ) -> dict:
        metadata = (
            server_metadata
            if server_metadata is not None
            else await self.get_server_metadata(login_provider)
        )
        userinfo_endpoint = metadata.get("userinfo_endpoint")
        if not userinfo_endpoint:
            raise InternalServerError(
                "G2P-AUT-502",
                "userinfo endpoint missing for provider.",
            )
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            content_type = response.headers.get("content-type", "")
            if content_type.startswith("application/json"):
                return response.json()
            if content_type.startswith("application/jwt"):
                return jose_jwt.get_unverified_claims(response.text)
            return {}

    async def introspect_token(
        self,
        login_provider: LoginProvider,
        token: str,
        endpoint: str | None = None,
        server_metadata: dict | None = None,
    ) -> dict:
        metadata = (
            server_metadata
            if server_metadata is not None
            else await self.get_server_metadata(login_provider)
        )
        introspection_endpoint = endpoint or metadata.get("introspection_endpoint")
        if not introspection_endpoint:
            raise InternalServerError(
                "G2P-AUT-502",
                "introspection endpoint missing for provider.",
            )

        auth = None
        data = {"token": token}
        method = login_provider.token_endpoint_auth_method.value
        if method == TokenEndpointAuthMethod.client_secret_basic.value:
            auth = (login_provider.client_id, login_provider.client_secret or "")
        else:
            data["client_id"] = login_provider.client_id
            if login_provider.client_secret:
                data["client_secret"] = login_provider.client_secret

        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(introspection_endpoint, auth=auth, data=data)
            response.raise_for_status()
            payload = response.json()
            if not payload.get("active"):
                raise UnauthorizedError(message="Unauthorized. Inactive token.")
            return payload
