from typing import Annotated

from fastapi import Depends, Request, Response
from fastapi.responses import RedirectResponse
from datetime import datetime, timedelta, timezone
from openg2p_fastapi_common.controller import BaseController
from iam_core.schemas import (
    AuthPrincipal,
    LoginProviderHttpResponse,
    StartAuthTransactionResponse,
)
from iam_core.services import AuthService
from iam_core.user_auth.dependencies import auth_principal, require_user_type

from ..config import Settings

_config = Settings.get_config(strict=False)


class AuthController(BaseController):
    user_type = "staff"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.router.prefix += "/auth"
        self.router.tags += ["/auth"]
        self.auth_service = AuthService(user_type=self.user_type)

        self.router.add_api_route("/get_user_profile", self.get_user_profile, methods=["GET"])
        self.router.add_api_route("/logout", self.logout, methods=["POST"])
        self.router.add_api_route(
            "/get_login_providers",
            self.get_login_providers,
            responses={200: {"model": LoginProviderHttpResponse}},
            methods=["GET"],
        )
        self.router.add_api_route(
            "/start_authentication_transaction",
            self.start_authentication_transaction,
            responses={200: {"model": StartAuthTransactionResponse}},
            methods=["POST"],
        )
        self.router.add_api_route("/callback", self.oauth_callback, methods=["GET"])

    async def get_user_profile(
        self,
        auth: Annotated[
            AuthPrincipal,
            Depends(require_user_type("staff", auth_dependency=auth_principal)),
        ],
    ):
        return auth.model_dump(exclude={"credentials", "raw_claims"})

    async def logout(self, response: Response):
        response.delete_cookie("X-Access-Token")
        response.delete_cookie("X-ID-Token")

    async def get_login_providers(self):
        return await self.auth_service.get_login_providers()

    async def start_authentication_transaction(self, id: int, redirect_uri: str = "/"):
        return await self.auth_service.start_authentication_transaction(
            provider_id=id,
            redirect_uri=redirect_uri,
        )

    async def oauth_callback(self, request: Request):
        result = await self.auth_service.complete_authentication_transaction(
            state_value=request.query_params.get("state"),
            code=request.query_params.get("code"),
        )
        token_response = result["token_response"]
        redirect_uri = result["redirect_uri"]
        expires_in = None
        if _config.auth_cookie_set_expires:
            seconds = token_response.get("expires_in")
            if seconds:
                expires_in = datetime.now(tz=timezone.utc) + timedelta(seconds=seconds)

        response = RedirectResponse(redirect_uri)
        response.set_cookie(
            "X-Access-Token",
            token_response["access_token"],
            max_age=_config.auth_cookie_max_age,
            expires=expires_in,
            path=_config.auth_cookie_path,
            domain=_config.auth_cookie_domain,
            httponly=_config.auth_cookie_httponly,
            secure=_config.auth_cookie_secure,
        )
        response.set_cookie(
            "X-ID-Token",
            token_response["id_token"],
            max_age=_config.auth_cookie_max_age,
            expires=expires_in,
            path=_config.auth_cookie_path,
            domain=_config.auth_cookie_domain,
            httponly=_config.auth_cookie_httponly,
            secure=_config.auth_cookie_secure,
        )
        return response
