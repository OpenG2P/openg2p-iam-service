import logging
from typing import List, Dict, Any

from openg2p_fastapi_common.errors.http_exceptions import InternalServerError
from openg2p_fastapi_common.service import BaseService

from ..config import Settings
from ..context import user_fields_cache
from ..models.orm.auth_oauth_provider_orm import AuthOauthProviderORM
from ..models.orm.user_orm import UserORM
from ..models.user_schemas import UserCreate
from ..utils.user_utils import create_user_process_gender, create_user_process_birthdate


_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class UserService(BaseService):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    async def check_and_create_user(
        self, validation: dict, id_type_config: dict = None
    ) -> UserORM:
        """
        Checks if a user exists based on unique_user_id, creates if not.
        """
        if not (id_type_config and id_type_config.get("g2p_id_type")):
            raise InternalServerError(
                message="Invalid Auth Provider Configuration. ID Type not configured."
            )

        validation: Dict[str, Any] = AuthOauthProviderORM.map_validation_response(
            validation, id_type_config["token_map"]
        )

        existing_user: UserORM = await UserORM.get_user_by_unique_user_id(
            validation["unique_user_id"]
        )
        if existing_user:
            return existing_user

        user_create: UserCreate = UserCreate(
            name=validation.get("name", ""),
            unique_user_id=validation["unique_user_id"],
            id_type=id_type_config.get("g2p_id_type"),
            user_id=validation.get("user_id"),
            email=validation.get("email"),
            gender=create_user_process_gender(validation.get("gender")),
            birthdate=create_user_process_birthdate(
                validation.get("birthdate"), date_format=id_type_config["date_format"]
            ),
            phone_number=validation.get("phone"),
            user_type=id_type_config.get("user_type"),
            auth_provider_id=id_type_config.get("auth_provider_id"),
        )

        user: UserORM = await UserORM.create_user(user_create=user_create)
        return user

    async def get_user_fields(self) -> List[str]:
        fields: List[str] = user_fields_cache.get()
        if fields:
            return fields
        fields = await UserORM.get_user_fields()
        user_fields_cache.set(fields)
        return fields
