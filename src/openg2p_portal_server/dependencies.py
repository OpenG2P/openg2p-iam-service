from typing import Optional

from fastapi import Request
from fastapi.security import HTTPAuthorizationCredentials
from openg2p_fastapi_auth.dependencies import JwtBearerAuth as BaseJwtBearerAuth
from openg2p_fastapi_auth.models.credentials import AuthCredentials as OriginalAuthCredentials
from openg2p_fastapi_common.errors.http_exceptions import InternalServerError, UnauthorizedError

from .models.credentials import AuthCredentials
from .models.orm.auth_oauth_provider import AuthOauthProviderORM
from .models.orm.user_orm import UserORM


class JwtBearerAuth(BaseJwtBearerAuth):
    async def __call__(
        self, request: Request
    ) -> Optional[HTTPAuthorizationCredentials]:
        res: OriginalAuthCredentials = await super().__call__(request)
        if not res:
            return None

        id_type_config = await AuthOauthProviderORM.get_auth_id_type_config(iss=res.iss)
        if not (id_type_config and id_type_config.get("g2p_id_type", None)):
            raise InternalServerError(
                message="Unauthorized. Invalid Auth Provider. ID Type not configured."
            )

        mapped_res = AuthOauthProviderORM.map_validation_response(
            res.model_dump(), id_type_config["token_map"]
        )

        user = await UserORM.get_user_by_user_id(mapped_res.get("user_id"))
        if not user:
            raise UnauthorizedError(
                message="Unauthorized. User Not Found."
            )

        new_res = AuthCredentials(user_id=user.id, **res.model_dump())
        return new_res
