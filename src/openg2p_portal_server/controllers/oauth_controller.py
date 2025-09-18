import orjson
from fastapi import Request
from openg2p_fastapi_auth.controllers.oauth_controller import OAuthController as BaseOAuthController
from openg2p_fastapi_common.utils import cookie_utils

from ..config import Settings
from ..models.orm.auth_oauth_provider_orm import AuthOauthProviderORM
from ..models.orm.user_login_orm import UserLoginORM

from ..services.user_service import UserService

_config = Settings.get_config()


class OAuthController(BaseOAuthController):
    """
    OAuthController handles OAuth authentication flows and callbacks.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.user_service = UserService.get_component()

    async def oauth_callback(self, request: Request):
        """
        Handles the OAuth callback after a user has authenticated with an OAuth provider.
        """
        query_params = request.query_params
        state = orjson.loads(query_params.get("state", "{}"))
        auth_provider_id = state.get("p", None)

        # Call the base OAuth callback to handle standard OAuth flow
        res = await super().oauth_callback(request)

        # Retrieve user info from the auth provider using tokens from cookies
        userinfo_dict = await self.auth_controller.get_oauth_validation_data(
            auth=cookie_utils.get_response_cookies(res, "X-Access-Token")[-1],
            id_token=cookie_utils.get_response_cookies(res, "X-ID-Token")[-1],
            provider=await self.auth_controller.get_login_provider_db_by_id(
                auth_provider_id
            ),
        )

        # Fetch ID type configuration for the OAuth provider
        id_type_config = await AuthOauthProviderORM.get_auth_id_type_config(
            id=auth_provider_id
        )

        # Create the user if not already present
        user = await self.user_service.check_and_create_user(
            userinfo_dict, id_type_config=id_type_config
        )

        # Create a login record for the user.
        await UserLoginORM.create_login_record(
            user_id=user.id,
            auth_provider_id=id_type_config.get("auth_provider_id"),
            id_type=id_type_config.get("g2p_id_type"),
        )

        return res
