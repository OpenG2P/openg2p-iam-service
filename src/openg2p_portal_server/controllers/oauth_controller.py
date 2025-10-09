import orjson
import logging

from typing import Optional, Dict, Any

from fastapi import Request, Response
from openg2p_fastapi_auth.controllers.oauth_controller import (
    OAuthController as BaseOAuthController,
)
from openg2p_fastapi_common.utils import cookie_utils

from ..config import Settings
from ..models.orm.auth_oauth_provider_orm import AuthOauthProviderORM
from ..models.orm.user_login_orm import UserLoginORM
from ..models.orm.user_orm import UserORM

from ..services.user_service import UserService

_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)


class OAuthController(BaseOAuthController):
    """
    OAuthController handles OAuth authentication flows and callbacks.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.user_service = UserService.get_component()

    async def oauth_callback(self, request: Request) -> Response:
        """
        Handles the OAuth callback after a user has authenticated with
        an OAuth provider.
        """
        _logger.info("OAuth callback")
        query_params = request.query_params
        state = orjson.loads(query_params.get("state", "{}"))
        auth_provider_id = state.get("p", None)

        _logger.debug(f"Parsed state: {state}, auth_provider_id={auth_provider_id}")

        # Call the base OAuth callback to handle standard OAuth flow
        res = await super().oauth_callback(request)
        _logger.debug("Base OAuth callback completed")

        # Retrieve user info from the auth provider using tokens from cookies
        access_token = cookie_utils.get_response_cookies(res, "X-Access-Token")[-1]
        id_token = cookie_utils.get_response_cookies(res, "X-ID-Token")[-1]

        _logger.debug("Fetching OAuth validation data from provider")
        login_provider = await self.auth_controller.get_login_provider_db_by_id(
            auth_provider_id
        )
        userinfo_dict = await self.auth_controller.get_oauth_validation_data(
            auth=access_token,
            id_token=id_token,
            provider=login_provider,
        )
        _logger.debug(f"Userinfo received: {userinfo_dict}")

        # Fetch ID type configuration for the OAuth provider
        id_type_config: Optional[
            Dict[str, Any]
        ] = await AuthOauthProviderORM.get_auth_id_type_config(id=auth_provider_id)
        _logger.debug(f"ID type config fetched: {id_type_config}")

        # Create the user if not already present
        _logger.debug("Checking if user exists or needs creation")
        user: UserORM = await self.user_service.check_and_create_user(
            userinfo_dict, id_type_config=id_type_config
        )
        _logger.debug(f"User ensured: {user}")

        # Create a login record for the user.
        _logger.debug("Creating user login record")
        await UserLoginORM.create_login_record(
            user_id=user.id,
            auth_provider_id=id_type_config.get("auth_provider_id"),
            provider_unique_id_type=id_type_config.get("g2p_id_type"),
            user_type=user.user_type,
        )

        _logger.info("OAuth callback completed successfully")
        return res
