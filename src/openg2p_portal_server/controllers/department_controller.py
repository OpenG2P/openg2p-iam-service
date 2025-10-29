import logging

from typing import List, Annotated

from fastapi import Depends
from openg2p_fastapi_common.controller import BaseController
from openg2p_fastapi_auth.auth.factory import AuthFactory
from openg2p_fastapi_auth_models.schemas import AuthCredentials

from ..models import Department
from ..schemas import DepartmentResponse
from ..services.user_service import UserService
from ..config import Settings


_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)


class DepartmentController(BaseController):
    """
    DepartmentController handles operations related to departments.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._user_service = UserService.get_component()

        self.router.add_api_route(
            "/departments",
            self.get_departments,
            responses={200: {"model": List[DepartmentResponse]}},
            methods=["POST"],
        )

    async def get_departments(
        self, auth: Annotated[AuthCredentials, Depends(AuthFactory())]
    ) -> List[DepartmentResponse]:
        """
        Returns all active departments.
        """
        _logger.info("Retrieving all active departments")
        departments = await Department.get_all_active()

        _logger.debug(f"Fetched {len(departments)} active departments")
        department_responses = [
            DepartmentResponse.model_validate(dept) for dept in departments
        ]

        _logger.info("All departments retrieved successfully")
        return department_responses
