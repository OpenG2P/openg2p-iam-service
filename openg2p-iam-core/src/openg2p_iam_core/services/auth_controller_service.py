import base64
import hashlib
import logging
import urllib.parse
from datetime import datetime, timedelta, timezone

import httpx
import orjson
from fastapi import HTTPException, Request, status
from fastapi.datastructures import QueryParams
from fastapi.responses import RedirectResponse
from jose import jwt
from openg2p_fastapi_common.errors.http_exceptions import (
    InternalServerError,
    UnauthorizedError,
)

from openg2p_iam_core.models import LoginProvider
from openg2p_iam_core.schemas import (
    LoginProviderHttpResponse,
    LoginProviderResponse,
    LoginProviderTypes,
    OauthClientAssertionType,
    OauthProviderParameters,
    StartAuthTransactionResponse,
)
from openg2p_iam_core.services.auth_transaction_store import auth_transaction_store
from openg2p_iam_core.user_auth.config import Settings

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class AuthControllerService:
    def __init__(self, user_type: str | None = None):
        self.user_type = user_type

    async def get_login_providers(self) -> LoginProviderHttpResponse:
        login_providers = await self.get_login_providers_db()
        return LoginProviderHttpResponse(
            loginProviders=[
                LoginProviderResponse(
                    id=lp.id,
                    name=lp.name,
                    type=lp.type,
                    displayName=lp.body,
                    displayIconUrl=lp.image_icon_url,
                )
                for lp in login_providers
            ],
        )

    async def start_authentication_transaction(
        self, id: int, redirect_uri: str = "/"
    ) -> StartAuthTransactionResponse:
        login_provider = await self.get_login_provider_or_404(id)
        redirect_url, state = await self.build_redirect_url_and_state(
            login_provider, redirect_uri
        )
        return StartAuthTransactionResponse(redirectUrl=redirect_url, state=state)

    async def get_login_provider_redirect(self, id: int, redirect_uri: str = "/"):
        login_provider = await self.get_login_provider_or_404(id)
        redirect_url, _ = await self.build_redirect_url_and_state(
            login_provider, redirect_uri
        )
        return RedirectResponse(redirect_url)

    async def oauth_callback(self, request: Request):
        state_value = request.query_params.get("state")
        txn = auth_transaction_store.get_and_pop(state_value)

        if txn:
            login_provider = await self.get_login_provider_db_by_id(txn.login_provider_id)
            res = await self.get_tokens(login_provider, request.query_params, txn=txn)
            id_claims = jwt.get_unverified_claims(res["id_token"])
            if id_claims.get("nonce") != txn.nonce:
                raise UnauthorizedError("G2P-AUT-401", "Nonce mismatch")
            redirect_uri = txn.redirect_uri
        else:
            # Backward-compatible fallback for old state format.
            state = orjson.loads(state_value or "{}")
            login_provider_id = state.get("p", None)
            if not login_provider_id:
                raise UnauthorizedError("G2P-AUT-401", "Login Provider Id not received")
            login_provider = await self.get_login_provider_db_by_id(login_provider_id)
            res = await self.get_tokens(login_provider, request.query_params, txn=None)
            redirect_uri = state.get("r", "/")

        config_dict = _config.model_dump()
        access_token: str = res["access_token"]
        id_token: str = res["id_token"]
        expires_in = None
        if config_dict.get("auth_cookie_set_expires", False):
            expires_in = res.get("expires_in", None)
            if expires_in:
                expires_in = datetime.now(tz=timezone.utc) + timedelta(seconds=expires_in)

        response = RedirectResponse(redirect_uri)
        response.set_cookie(
            "X-Access-Token",
            access_token,
            max_age=config_dict.get("auth_cookie_max_age", None),
            expires=expires_in,
            path=config_dict.get("auth_cookie_path", "/"),
            httponly=config_dict.get("auth_cookie_httponly", True),
            secure=config_dict.get("auth_cookie_secure", True),
        )
        response.set_cookie(
            "X-ID-Token",
            id_token,
            max_age=config_dict.get("auth_cookie_max_age", None),
            expires=expires_in,
            path=config_dict.get("auth_cookie_path", "/"),
            httponly=config_dict.get("auth_cookie_httponly", True),
            secure=config_dict.get("auth_cookie_secure", True),
        )
        return response

    async def get_login_provider_or_404(self, id: int) -> LoginProvider:
        try:
            login_provider = await self.get_login_provider_db_by_id(id)
        except Exception as e:
            _logger.exception("Login Provider fetching: Invalid Id")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Login Provider ID Not Found",
            ) from e
        if not login_provider:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Login Provider ID Not Found",
            )
        return login_provider

    async def build_redirect_url_and_state(
        self, login_provider: LoginProvider, redirect_uri: str
    ) -> tuple[str, str]:
        if login_provider.type != LoginProviderTypes.oauth2_auth_code.value:
            raise NotImplementedError()

        provider_data = {
            "auth_endpoint": login_provider.auth_endpoint,
            "token_endpoint": login_provider.token_endpoint,
            "validation_endpoint": login_provider.validation_endpoint,
            "jwks_uri": login_provider.jwks_uri,
            "client_id": login_provider.client_id,
            "client_secret": login_provider.client_secret,
            "oauth_callback_url": login_provider.oauth_callback_url,
            "scope": login_provider.scope or "openid profile email",
            "enable_pkce": login_provider.enable_pkce,
            "code_verifier": "",
            "extra_authorize_params": orjson.loads(
                login_provider.extra_authorize_params or "{}"
            ),
            "response_type": "code",
            "code_challenge": "",
            "code_challenge_method": "S256",
        }
        auth_parameters = OauthProviderParameters.model_validate(provider_data)
        txn = auth_transaction_store.create(
            login_provider_id=login_provider.id, redirect_uri=redirect_uri
        )
        authorize_query_params = {
            "client_id": auth_parameters.client_id,
            "response_type": auth_parameters.response_type,
            "redirect_uri": auth_parameters.oauth_callback_url,
            "scope": auth_parameters.scope,
            "nonce": txn.nonce,
            "state": txn.state,
        }
        if auth_parameters.enable_pkce:
            authorize_query_params.update(
                {
                    "code_challenge": self.pkce_build_code_challenge(
                        txn.code_verifier,
                        auth_parameters.code_challenge_method,
                    ),
                    "code_challenge_method": auth_parameters.code_challenge_method,
                }
            )

        authorize_query_params.update(auth_parameters.extra_authorize_params)
        return (
            f"{auth_parameters.auth_endpoint}?{urllib.parse.urlencode(authorize_query_params)}",
            txn.state,
        )

    def pkce_build_code_challenge(self, code_verifier: str, method: str) -> str:
        if method.lower() == "s256":
            return (
                base64.urlsafe_b64encode(
                    hashlib.sha256(code_verifier.encode("ascii")).digest()
                )
                .rstrip(b"=")
                .decode()
            )
        raise NotImplementedError()

    async def get_login_providers_db(self) -> list[LoginProvider]:
        if self.user_type:
            return await LoginProvider.get_by_user_type(self.user_type)
        return await LoginProvider.get_all()

    async def get_login_provider_db_by_id(self, id: int) -> LoginProvider:
        return await LoginProvider.get_by_id(id)

    async def get_login_provider_db_by_iss(self, iss: str) -> LoginProvider:
        if _config.login_providers_list:
            lp_fields = LoginProvider.__mapper__.columns.keys()
            for lp in _config.login_providers_list:
                if iss == lp.get("iss"):
                    return LoginProvider(
                        **{
                            lp_key: lp_val
                            for lp_key, lp_val in lp.items()
                            if lp_key in lp_fields
                        }
                    )
            return None
        if await LoginProvider.table_exists_cached():
            return await LoginProvider.get_login_provider_from_iss(iss)
        return None

    async def get_oauth_validation_data(
        self,
        auth: str,
        id_token: str = None,
        iss: str = None,
        login_provider: LoginProvider = None,
        combine=True,
    ) -> dict:
        access_token = auth
        if not login_provider:
            if not iss:
                iss = jwt.get_unverified_claims(access_token)["iss"]
            login_provider = await self.get_login_provider_db_by_iss(iss)
        provider_data = {
            "auth_endpoint": login_provider.auth_endpoint,
            "token_endpoint": login_provider.token_endpoint,
            "validation_endpoint": login_provider.validation_endpoint,
            "jwks_uri": login_provider.jwks_uri,
            "client_id": login_provider.client_id,
            "client_secret": login_provider.client_secret,
            "oauth_callback_url": login_provider.oauth_callback_url,
            "scope": login_provider.scope or "openid profile email",
            "enable_pkce": login_provider.enable_pkce,
            "code_verifier": "",
            "extra_authorize_params": orjson.loads(
                login_provider.extra_authorize_params or "{}"
            ),
            "client_assertion_type": OauthClientAssertionType[
                (
                    "client_secret"
                    if login_provider.client_authentication_method.startswith(
                        "client_secret"
                    )
                    else login_provider.client_authentication_method
                )
            ],
            "client_assertion_jwt_aud": login_provider.jwt_assertion_aud,
            "response_type": "code",
            "code_challenge": "",
            "code_challenge_method": "S256",
            "client_assertion_jwk": (
                base64.b64decode(login_provider.client_private_key)
                if login_provider.client_private_key
                else None
            ),
        }

        auth_params = OauthProviderParameters.model_validate(provider_data)
        try:
            response = httpx.get(
                auth_params.validation_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            if response.headers["content-type"].startswith("application/json"):
                res = response.json()
            elif response.headers["content-type"].startswith("application/jwt"):
                res = jwt.get_unverified_claims(response.content)
            if combine:
                return self.combine_tokens(access_token, id_token, res)
            return res
        except Exception as e:
            _logger.exception("Error fetching user profile.")
            raise InternalServerError(
                "G2P-AUT-502",
                f"Error fetching userinfo. {repr(e)}",
            ) from e

    async def get_tokens(
        self,
        login_provider: LoginProvider,
        query_params: QueryParams,
        txn=None,
        **kw,
    ):
        if login_provider.type != LoginProviderTypes.oauth2_auth_code.value:
            raise NotImplementedError()

        provider_data = {
            "auth_endpoint": login_provider.auth_endpoint,
            "token_endpoint": login_provider.token_endpoint,
            "validation_endpoint": login_provider.validation_endpoint,
            "jwks_uri": login_provider.jwks_uri,
            "client_id": login_provider.client_id,
            "client_secret": login_provider.client_secret,
            "oauth_callback_url": login_provider.oauth_callback_url,
            "scope": login_provider.scope or "openid profile email",
            "enable_pkce": login_provider.enable_pkce,
            "code_verifier": (
                txn.code_verifier
                if txn and login_provider.enable_pkce
                else login_provider.code_verifier or ""
            ),
            "extra_authorize_params": orjson.loads(
                login_provider.extra_authorize_params or "{}"
            ),
            "client_assertion_type": OauthClientAssertionType[
                (
                    "client_secret"
                    if login_provider.client_authentication_method.startswith(
                        "client_secret"
                    )
                    else login_provider.client_authentication_method
                )
            ],
            "client_assertion_jwt_aud": login_provider.jwt_assertion_aud,
            "response_type": "code",
            "code_challenge": "",
            "code_challenge_method": "S256",
            "client_assertion_jwk": (
                base64.b64decode(login_provider.client_private_key)
                if login_provider.client_private_key
                else None
            ),
        }
        auth_parameters = OauthProviderParameters.model_validate(provider_data)
        token_request_data = {
            "client_id": auth_parameters.client_id,
            "grant_type": "authorization_code",
            "redirect_uri": auth_parameters.oauth_callback_url,
            "code": query_params.get("code"),
        }
        if auth_parameters.enable_pkce:
            token_request_data["code_verifier"] = auth_parameters.code_verifier

        token_auth = None
        if auth_parameters.client_assertion_type.name.startswith("private_key_jwt"):
            await self.update_client_assertion(auth_parameters, token_request_data, **kw)
        elif (
            auth_parameters.client_assertion_type
            == OauthClientAssertionType.client_secret_basic
        ):
            token_auth = (auth_parameters.client_id, auth_parameters.client_secret)
        elif auth_parameters.client_assertion_type == OauthClientAssertionType.client_secret:
            token_request_data["client_secret"] = auth_parameters.client_secret
        try:
            res = httpx.post(
                auth_parameters.token_endpoint,
                auth=token_auth,
                data=orjson.loads(orjson.dumps(token_request_data)),
            )
            res.raise_for_status()
            return res.json()
        except Exception as e:
            _logger.exception(
                "Error while fetching token from token endpoint, %s",
                auth_parameters.token_endpoint,
            )
            raise UnauthorizedError(
                message="Unauthorized. Failed to get token from Oauth Server"
            ) from e

    async def update_client_assertion(
        self, auth_parameters: OauthProviderParameters, token_request_data: dict, **kw
    ):
        if (
            auth_parameters.client_assertion_type
            == OauthClientAssertionType.private_key_jwt
            or auth_parameters.client_assertion_type
            == OauthClientAssertionType.private_key_jwt_legacy
        ):
            client_assertion_type = auth_parameters.client_assertion_type.value
            client_assertion = jwt.encode(
                {
                    "iss": auth_parameters.client_id,
                    "sub": auth_parameters.client_id,
                    "aud": auth_parameters.client_assertion_jwt_aud
                    or auth_parameters.token_endpoint,
                    "exp": datetime.utcnow() + timedelta(hours=1),
                    "iat": datetime.utcnow(),
                },
                auth_parameters.client_assertion_jwk,
                algorithm="RS256",
            )
        elif (
            auth_parameters.client_assertion_type
            == OauthClientAssertionType.private_key_jwt_keymanager
        ):
            client_assertion_type = (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            )
            client_assertion = await self.generate_client_assertion_keymanager(
                auth_parameters, **kw
            )
        else:
            raise NotImplementedError()
        token_request_data.update(
            {
                "client_assertion_type": client_assertion_type,
                "client_assertion": client_assertion,
            }
        )

    async def generate_client_assertion_keymanager(
        self, auth_parameters: OauthProviderParameters, **kw
    ):
        app_id_ref_id = auth_parameters.client_assertion_jwk_keymanager
        if ":" in app_id_ref_id:
            km_app_id = auth_parameters.client_assertion_jwk_keymanager.split(":")[
                0
            ].strip()
            km_ref_id = auth_parameters.client_assertion_jwk_keymanager.split(":")[
                1
            ].strip()
        else:
            km_app_id = app_id_ref_id
            km_ref_id = ""
        iat = datetime.now(tz=timezone.utc).replace(tzinfo=None)
        exp = iat + timedelta(hours=1)
        keymanager_helper = kw.get("keymanager_helper")
        if not keymanager_helper:
            raise InternalServerError(
                "G2P-AUT-503", "Keymanager helper is required for keymanager flow."
            )
        return await keymanager_helper.create_jwt_token(
            {
                "iss": auth_parameters.client_id,
                "sub": auth_parameters.client_id,
                "aud": auth_parameters.client_assertion_jwt_aud
                or auth_parameters.token_endpoint,
                "iat": int(iat.timestamp()),
                "exp": int(exp.timestamp()),
            },
            km_app_id=km_app_id,
            km_ref_id=km_ref_id,
            **kw,
        )

    @classmethod
    def combine_token_dicts(cls, *token_dicts) -> dict:
        res = None
        for token_dict in token_dicts:
            if token_dict:
                if not res:
                    res = token_dict
                else:
                    for k, v in token_dict.items():
                        if v:
                            res[k] = v
        return res

    @classmethod
    def combine_tokens(cls, *tokens) -> dict:
        res = []
        for token in tokens:
            if token:
                try:
                    res.append(
                        jwt.get_unverified_claims(token) if isinstance(token, str) else token
                    )
                except Exception:
                    pass
        return cls.combine_token_dicts(*res)
