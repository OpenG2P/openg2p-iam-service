from typing import Annotated, List

from fastapi import Depends
from openg2p_fastapi_auth.controllers.auth_controller import AuthController as BaseAuthController
from openg2p_fastapi_auth.models.credentials import AuthCredentials
from openg2p_fastapi_common.errors.http_exceptions import UnauthorizedError

from ..dependencies import JwtBearerAuth
from ..models.orm.auth_oauth_provider_orm import AuthOauthProviderORM
from ..models.orm.user_orm import UserORM
from ..models.user_profile import GetUserProfile
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
            responses={200: {"model": GetUserProfile}},
            methods=["GET"],
        )

    @property
    def user_service(self):
        if not self._user_service:
            self._user_service = UserService.get_component()
        return self._user_service

    async def get_profile(
        self,
        auth: Annotated[AuthCredentials, Depends(JwtBearerAuth())],
        online: bool = True,
    ):
        """
        Retrieves the profile of the authenticated user.
        """
        if not auth.user_id:
            raise UnauthorizedError(message="Unauthorized. User Not Found.")

        user_data = await UserORM.get_user_by_id(auth.user_id)

        # Deserialize address if stored as JSON string

        return GetUserProfile(
            id=user_data.id,
            name=user_data.name,
            user_unique_id=user_data.user_unique_id,
            id_type=user_data.id_type,
            email=user_data.email,
            gender=user_data.gender,
            birthdate=user_data.birthdate,
            phone_number=user_data.phone_number,
            user_type=user_data.user_type,
        )

    async def get_login_providers_db(self) -> List:
        """
        Returns all login providers configured in the database.
        """
        return [
            ap.map_auth_provider_to_login_provider()
            for ap in await AuthOauthProviderORM.get_all()
        ]

    async def get_login_provider_db_by_id(self, id: int):
        """
        Returns a login provider by its ID.
        """
        ap = await AuthOauthProviderORM.get_by_id(id)
        return ap.map_auth_provider_to_login_provider() if ap else None

    async def get_login_provider_db_by_iss(self, iss: str):
        """
        Returns a login provider by its issuer (iss).
        """
        ap = await AuthOauthProviderORM.get_auth_provider_from_iss(iss)
        return ap.map_auth_provider_to_login_provider() if ap else None
