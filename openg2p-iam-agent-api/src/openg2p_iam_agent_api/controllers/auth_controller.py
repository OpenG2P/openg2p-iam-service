from typing import Annotated

from fastapi import Depends, Request, Response
from openg2p_fastapi_common.controller import BaseController
from openg2p_fastapi_common.errors.http_exceptions import ForbiddenError
from openg2p_iam_core.schemas import (
    AuthPrincipal,
    LoginProviderHttpResponse,
    StartAuthTransactionResponse,
)
from openg2p_iam_core.services import AuthControllerService
from openg2p_iam_core.user_auth.auth import AgentAuthAdapter


class AuthController(BaseController):
    user_type = "agent"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.router.prefix += "/auth"
        self.router.tags += ["auth"]
        self.auth_controller_service = AuthControllerService(user_type=self.user_type)

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
        self.router.add_api_route(
            "/get_login_provider_redirect/{id}",
            self.get_login_provider_redirect,
            methods=["GET"],
        )
        self.router.add_api_route("/callback", self.oauth_callback, methods=["GET"])

    async def get_user_profile(
        self, auth: Annotated[AuthPrincipal, Depends(AgentAuthAdapter())]
    ):
        if auth.user_type != self.user_type:
            raise ForbiddenError(message="Forbidden. Invalid userType.")
        return auth.model_dump(exclude={"credentials", "raw_claims"})

    async def logout(self, response: Response):
        response.delete_cookie("X-Access-Token")
        response.delete_cookie("X-ID-Token")

    async def get_login_providers(self):
        return await self.auth_controller_service.get_login_providers()

    async def start_authentication_transaction(self, id: int, redirect_uri: str = "/"):
        return await self.auth_controller_service.start_authentication_transaction(
            id=id, redirect_uri=redirect_uri
        )

    async def get_login_provider_redirect(self, id: int, redirect_uri: str = "/"):
        return await self.auth_controller_service.get_login_provider_redirect(
            id=id, redirect_uri=redirect_uri
        )

    async def oauth_callback(self, request: Request):
        return await self.auth_controller_service.oauth_callback(request)
