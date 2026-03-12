import base64
import json
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.jose import JsonWebKey, jwt
from jose import jwt as jose_jwt
from openg2p_fastapi_common.errors.http_exceptions import InternalServerError, UnauthorizedError

from openg2p_iam_core.context import jwks_cache, server_metadata_cache
from openg2p_iam_core.models import LoginProvider
from openg2p_iam_core.schemas import TokenEndpointAuthMethod

from .config import Settings

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class AuthlibOidcService:
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

        # Provider model values override discovery so local config remains authoritative.
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

    async def _get_jwks(self, login_provider: LoginProvider, iss: str | None = None) -> dict:
        metadata = await self.get_server_metadata(login_provider)
        issuer = iss or metadata.get("issuer") or self._guess_issuer(login_provider)
        cache = jwks_cache.get() or {}
        if issuer and issuer in cache:
            return cache[issuer]

        jwks_url = metadata.get("jwks_uri")
        if not jwks_url and issuer:
            jwks_url = f"{issuer.rstrip('/')}/.well-known/jwks.json"
        if not jwks_url:
            raise InternalServerError(
                code="G2P-AUT-500",
                message="Missing jwks_uri for provider.",
            )

        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(jwks_url)
            response.raise_for_status()
            jwks = response.json()

        if issuer:
            cache[issuer] = jwks
            jwks_cache.set(cache)
        return jwks

    @staticmethod
    def _pkce_kwargs(login_provider: LoginProvider, code_verifier: str | None) -> dict:
        if login_provider.enable_pkce and code_verifier:
            return {"code_verifier": code_verifier}
        return {}

    @staticmethod
    def _token_endpoint_auth_method(
        login_provider: LoginProvider,
    ) -> TokenEndpointAuthMethod:
        return login_provider.token_endpoint_auth_method

    async def _generate_client_assertion(
        self,
        login_provider: LoginProvider,
        keymanager_helper=None,
        **kw,
    ) -> tuple[str, str]:
        assertion_type = self._token_endpoint_auth_method(login_provider)
        aud = login_provider.jwt_assertion_aud or login_provider.token_endpoint

        if assertion_type in (
            TokenEndpointAuthMethod.private_key_jwt,
        ):
            if not login_provider.client_private_key:
                raise InternalServerError(
                    "G2P-AUT-503",
                    "client_private_key is required for private_key_jwt.",
                )
            encoded_private_key = base64.b64decode(login_provider.client_private_key)
            private_key = JsonWebKey.import_key(encoded_private_key)
            payload = {
                "iss": login_provider.client_id,
                "sub": login_provider.client_id,
                "aud": aud,
                "exp": datetime.utcnow() + timedelta(hours=1),
                "iat": datetime.utcnow(),
            }
            token = jwt.encode({"alg": "RS256"}, payload, private_key).decode("utf-8")
            return assertion_type.value, token

        if assertion_type == TokenEndpointAuthMethod.private_key_jwt_keymanager:
            if not keymanager_helper:
                raise InternalServerError(
                    "G2P-AUT-503",
                    "Keymanager helper is required for keymanager flow.",
                )
            app_id_ref_id = login_provider.client_private_key.decode("utf-8")
            if ":" in app_id_ref_id:
                km_app_id, km_ref_id = [x.strip() for x in app_id_ref_id.split(":", 1)]
            else:
                km_app_id, km_ref_id = app_id_ref_id, ""
            iat = datetime.now(tz=timezone.utc).replace(tzinfo=None)
            exp = iat + timedelta(hours=1)
            token = await keymanager_helper.create_jwt_token(
                {
                    "iss": login_provider.client_id,
                    "sub": login_provider.client_id,
                    "aud": aud,
                    "iat": int(iat.timestamp()),
                    "exp": int(exp.timestamp()),
                },
                km_app_id=km_app_id,
                km_ref_id=km_ref_id,
                **kw,
            )
            return (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                token,
            )

        raise InternalServerError(
            "G2P-AUT-503",
            "Unsupported client assertion configuration.",
        )

    async def build_authorize_redirect(
        self, login_provider: LoginProvider, state: str, nonce: str, code_verifier: str
    ) -> tuple[str, str]:
        metadata = await self.get_server_metadata(login_provider)
        auth_endpoint = metadata.get("authorization_endpoint")
        if not auth_endpoint:
            raise InternalServerError("G2P-AUT-500", "authorization_endpoint missing.")

        extra = self._extra_params(login_provider)
        client = AsyncOAuth2Client(client_id=login_provider.client_id)
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
        params.update(extra)
        return client.create_authorization_url(auth_endpoint, **params)

    async def exchange_code_for_token(
        self,
        login_provider: LoginProvider,
        code: str,
        code_verifier: str | None = None,
        keymanager_helper=None,
        **kw,
    ) -> dict:
        metadata = await self.get_server_metadata(login_provider)
        token_endpoint = metadata.get("token_endpoint")
        if not token_endpoint:
            raise UnauthorizedError(message="Unauthorized. Missing token endpoint.")

        token_auth_method = self._token_endpoint_auth_method(login_provider)
        client_kwargs = {}
        token_kwargs = {
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": login_provider.oauth_callback_url,
        }
        token_kwargs.update(self._pkce_kwargs(login_provider, code_verifier))

        if token_auth_method == TokenEndpointAuthMethod.client_secret_basic:
            client_kwargs["client_secret"] = login_provider.client_secret
            client_kwargs["token_endpoint_auth_method"] = "client_secret_basic"
        elif token_auth_method == TokenEndpointAuthMethod.client_secret_post:
            client_kwargs["client_secret"] = login_provider.client_secret
            client_kwargs["token_endpoint_auth_method"] = "client_secret_post"
        else:
            client_kwargs["token_endpoint_auth_method"] = "client_secret_post"
            assertion_type, assertion = await self._generate_client_assertion(
                login_provider,
                keymanager_helper=keymanager_helper,
                **kw,
            )
            token_kwargs["client_assertion_type"] = assertion_type
            token_kwargs["client_assertion"] = assertion

        client = AsyncOAuth2Client(
            client_id=login_provider.client_id,
            **client_kwargs,
        )
        token = await client.fetch_token(token_endpoint, **token_kwargs)
        return dict(token)

    async def decode_jwt(
        self,
        login_provider: LoginProvider,
        token: str,
        verify_exp: bool = True,
        nonce: str | None = None,
        access_token: str | None = None,
        iss: str | None = None,
    ) -> dict:
        jwks = await self._get_jwks(login_provider, iss=iss)
        key_set = JsonWebKey.import_key_set(jwks)
        claims = jwt.decode(token, key_set, claims_params={"nonce": nonce})
        if verify_exp:
            claims.validate()
        claim_dict = dict(claims)
        if nonce and claim_dict.get("nonce") != nonce:
            raise UnauthorizedError("G2P-AUT-401", "Nonce mismatch")
        if access_token and claim_dict.get("at_hash") is None:
            _logger.debug("ID token missing at_hash while access_token is present.")
        return claim_dict

    async def get_oauth_validation_data(
        self, login_provider: LoginProvider, access_token: str
    ) -> dict:
        metadata = await self.get_server_metadata(login_provider)
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
    ) -> dict:
        metadata = await self.get_server_metadata(login_provider)
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
