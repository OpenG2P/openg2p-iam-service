from datetime import datetime, timedelta, timezone

from fastapi import Request
from fastapi.responses import RedirectResponse
from iam_core.services import AuthService
from openg2p_fastapi_common.controller import BaseController

from ..config import Settings

_config = Settings.get_config(strict=False)


class OAuthCallbackController(BaseController):
    '''
    Controller for handling the OAuth callback endpoint, which completes the authentication transaction and sets the necessary cookies for authenticated sessions.
    '''
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.router.prefix += "/auth"
        self.router.tags += ["/auth"]
        self.auth_service = AuthService()

        self.router.add_api_route("/callback", self.oauth_callback, methods=["GET"])

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
