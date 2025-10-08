import logging

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
from ..models.orm.department_orm import DepartmentORM
from ..models.user_schemas import UserResponse, DepartmentResponse
from ..services.user_service import UserService
from ..config import Settings


_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)


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
        
        # Register GET /departments endpoint
        self.router.add_api_route(
            "/departments",
            self.get_departments,
            responses={200: {"model": List[DepartmentResponse]}},
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
        _logger.info("Fetching user profile")
        if not auth.user_id:
            _logger.error("Unauthorized access attempt: missing user_id in token")
            raise UnauthorizedError(message="Unauthorized. User Not Found.")

        _logger.debug(f"Looking up user by ID: {auth.user_id}")
        user: UserORM = await UserORM.get_user_by_id(auth.user_id)

        _logger.debug(f"User found: {user}")
        
        # Get departments for the user
        departments = await DepartmentORM.get_all_active()
        department_responses = [DepartmentResponse.model_validate(dept) for dept in departments]
        
        user_response: UserResponse = UserResponse.model_validate(user)
        user_response.departments = department_responses

        _logger.info("User profile fetched successfully")
        return user_response

    async def get_departments(self) -> List[DepartmentResponse]:
        """
        Returns all active departments.
        """
        _logger.info("Retrieving all active departments")
        departments = await DepartmentORM.get_all_active()
        
        _logger.debug(f"Fetched {len(departments)} active departments")
        department_responses = [DepartmentResponse.model_validate(dept) for dept in departments]
        
        _logger.info("All departments retrieved successfully")
        return department_responses

    async def get_login_providers_db(self) -> List[LoginProvider]:
        """
        Returns all login providers configured in the database.
        """
        _logger.info("Retrieving all login providers from database")
        auth_providers: List[AuthOauthProviderORM] = (
            await AuthOauthProviderORM.get_all()
        )

        _logger.debug(f"Fetched {len(auth_providers)} auth providers from DB")
        login_providers: List[LoginProvider] = [
            auth_provider.map_auth_provider_to_login_provider()
            for auth_provider in auth_providers
        ]

        _logger.info("All login providers retrieved successfully")
        return login_providers

    async def get_login_provider_db_by_id(self, id: int) -> Optional[LoginProvider]:
        """
        Returns a login provider by its ID.
        """
        _logger.info(f"Retrieving login provider by ID {id}")
        auth_provider: Optional[AuthOauthProviderORM] = (
            await AuthOauthProviderORM.get_by_id(id)
        )

        if not auth_provider:
            _logger.error(f"No login provider found for ID {id}")
            return None

        login_provider: Optional[LoginProvider] = (
            auth_provider.map_auth_provider_to_login_provider()
        )

        _logger.info(f"Retrieved login provider by ID {id} successfully")
        return login_provider

    async def get_login_provider_db_by_iss(self, iss: str) -> Optional[LoginProvider]:
        """
        Returns a login provider by its issuer (iss).
        """
        _logger.info(f"Retrieving login provider by issuer '{iss}'")
        auth_provider: Optional[AuthOauthProviderORM] = (
            await AuthOauthProviderORM.get_auth_provider_from_iss(iss)
        )

        if not auth_provider:
            _logger.error(f"No login provider found for issuer '{iss}'")
            return None

        login_provider: Optional[LoginProvider] = (
            auth_provider.map_auth_provider_to_login_provider()
        )

        _logger.info(f"Retrieved login provider by issuer '{iss}' successfully")
        return login_provider
