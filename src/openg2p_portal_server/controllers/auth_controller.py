from typing import Annotated, List, Optional

from fastapi import Depends
from openg2p_fastapi_auth.controllers.auth_controller import (
    AuthController as BaseAuthController,
)
from openg2p_fastapi_auth.models.credentials import AuthCredentials
from openg2p_fastapi_common.errors.http_exceptions import UnauthorizedError
from openg2p_fastapi_auth.models.orm.login_provider import LoginProvider

from ..dependencies import JwtBearerAuth
from ..models.orm.auth_oauth_provider_orm import AuthOauthProviderORM
from ..models.orm.user_orm import UserORM
from ..models.user_schemas import UserResponse
from ..services.user_service import UserService


class AuthController(BaseAuthController):
    """
    AuthController handles authentication and profile retrieval for users.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._user_service = UserService.get_component()

        # Register GET /profile endpoint
        self.router.add_api_route(
            "/profile",
            self.get_profile,
            responses={200: {"model": UserResponse}},
            methods=["GET"],
        )

    @property
    def user_service(self) -> UserService:
        if not self._user_service:
            self._user_service = UserService.get_component()
        return self._user_service

    async def get_profile(
        self,
        auth: Annotated[AuthCredentials, Depends(JwtBearerAuth())],
        online: bool = True,
    ) -> UserResponse:
        """
        Retrieves the profile of the authenticated user.
        """
        if not auth.user_id:
            raise UnauthorizedError(message="Unauthorized. User Not Found.")

        user: UserORM = await UserORM.get_user_by_id(auth.user_id)

        user_response: UserResponse = UserResponse.model_validate(user)

        return user_response

    async def get_login_providers_db(self) -> List[LoginProvider]:
        """
        Returns all login providers configured in the database.
        """
        auth_providers: List[AuthOauthProviderORM] = (
            await AuthOauthProviderORM.get_all()
        )
        login_providers: List[LoginProvider] = [
            provider.map_auth_provider_to_login_provider()
            for provider in auth_providers
        ]
        return login_providers

    async def get_login_provider_db_by_id(self, id: int) -> Optional[LoginProvider]:
        """
        Returns a login provider by its ID.
        """
        auth_provider: Optional[AuthOauthProviderORM] = (
            await AuthOauthProviderORM.get_by_id(id)
        )
        login_provider: Optional[LoginProvider] = (
            auth_provider.map_auth_provider_to_login_provider()
            if auth_provider
            else None
        )
        return login_provider

    async def get_login_provider_db_by_iss(self, iss: str) -> Optional[LoginProvider]:
        """
        Returns a login provider by its issuer (iss).
        """
        auth_provider: Optional[AuthOauthProviderORM] = (
            await AuthOauthProviderORM.get_auth_provider_from_iss(iss)
        )
        login_provider: Optional[LoginProvider] = (
            auth_provider.map_auth_provider_to_login_provider()
            if auth_provider
            else None
        )
        return login_provider
