import logging
from datetime import datetime

import orjson
from openg2p_fastapi_common.context import dbengine
from openg2p_fastapi_common.errors.http_exceptions import InternalServerError
from openg2p_fastapi_common.service import BaseService
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker

from ..config import Settings
from ..context import user_fields_cache
from ..models.orm.auth_oauth_provider import AuthOauthProviderORM
from ..models.orm.user_orm import UserORM

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class UserService(BaseService):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    async def check_and_create_user(
        self, validation: dict, id_type_config: dict = None
    ):
        if not (id_type_config and id_type_config.get("g2p_id_type", None)):
            raise InternalServerError(
                message="Invalid Auth Provider Configuration. ID Type not configured."
            )

        validation = AuthOauthProviderORM.map_validation_response(
            validation, id_type_config["token_map"]
        )

        async_session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with async_session_maker() as session:
            stmt = select(UserORM).filter(UserORM.individual_id == validation["individual_id"])
            result = await session.execute(stmt)
            user = result.scalar()

            if user:
                return user

            user_dict = {
                "name": validation.get("name", ""),
                "individual_id": validation["individual_id"],
                "user_id": validation["user_id"],
                "email": validation.get("email"),
                "gender": self.create_user_process_gender(validation.get("gender")),
                "birthdate": self.create_user_process_birthdate(
                    validation.get("birthdate"), date_format=id_type_config["date_format"]
                ),
                "phone_number": validation.get("phone"),
                "user_type": id_type_config.get("user_type"),
                "auth_provider_id": id_type_config.get("auth_provider_id"),
                "active": True,
            }

            address = validation.get("address")
            if address and isinstance(address, dict):
                user_dict["address"] = orjson.dumps(address).decode()

            try:
                user = UserORM(**user_dict)
                session.add(user)
                await session.commit()
                return user
            except IntegrityError as e:
                raise InternalServerError(
                    message=f"Could not create user. {repr(e)}"
                ) from e

    def create_user_process_gender(self, gender):
        return gender.capitalize() if gender else None

    def create_user_process_birthdate(self, birthdate, date_format="%Y/%m/%d"):
        if not birthdate:
            return None
        return datetime.strptime(birthdate, date_format).date()

    async def get_user_fields(self):
        fields = user_fields_cache.get()
        if fields:
            return fields
        fields = await UserORM.get_user_fields()
        user_fields_cache.set(fields)
        return fields
