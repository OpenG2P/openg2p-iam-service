import base64
from typing import List, Optional

import orjson
from openg2p_fastapi_auth.models.login_provider import LoginProviderTypes
from openg2p_fastapi_auth.models.orm.login_provider import LoginProvider
from openg2p_fastapi_auth.models.provider_auth_parameters import (
    OauthClientAssertionType,
    OauthProviderParameters,
)
from openg2p_fastapi_common.context import dbengine
from openg2p_fastapi_common.models import BaseORMModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column

from ...context import auth_id_type_config_cache


class AuthOauthProviderORM(BaseORMModel):
    __tablename__ = "auth_oauth_provider"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column()
    flow: Mapped[Optional[str]] = mapped_column()
    body: Mapped[Optional[str]] = mapped_column()
    image_icon_url: Mapped[Optional[str]] = mapped_column()
    client_id: Mapped[Optional[str]] = mapped_column()
    client_authentication_method: Mapped[str] = mapped_column()
    client_secret: Mapped[Optional[str]] = mapped_column()
    client_private_key: Mapped[Optional[bytes]] = mapped_column()
    auth_endpoint: Mapped[str] = mapped_column()
    validation_endpoint: Mapped[Optional[str]] = mapped_column()
    token_endpoint: Mapped[Optional[str]] = mapped_column()
    jwks_uri: Mapped[Optional[str]] = mapped_column()
    jwt_assertion_aud: Mapped[Optional[str]] = mapped_column()
    scope: Mapped[Optional[str]] = mapped_column()
    enable_pkce: Mapped[Optional[str]] = mapped_column()
    code_verifier: Mapped[Optional[str]] = mapped_column()
    date_format: Mapped[Optional[str]] = mapped_column()
    token_map: Mapped[str] = mapped_column()
    extra_authorize_params: Mapped[Optional[str]] = mapped_column()
    g2p_portal_oauth_callback_url: Mapped[Optional[str]] = mapped_column()
    g2p_id_type: Mapped[Optional[str]] = mapped_column()

    @classmethod
    async def get_by_id(cls, id: int) -> "AuthOauthProviderORM":
        async_session_maker = async_sessionmaker(dbengine.get())
        async with async_session_maker() as session:
            return await session.get(cls, id)

    @classmethod
    async def get_all(cls) -> List["AuthOauthProviderORM"]:
        response = []
        async_session_maker = async_sessionmaker(dbengine.get())
        async with async_session_maker() as session:
            stmt = select(cls).order_by(cls.id.asc())
            result = await session.execute(stmt)
            response = list(result.scalars())
        return response

    @classmethod
    async def get_auth_provider_from_iss(cls, iss: str) -> "AuthOauthProviderORM":
        response = None
        async_session_maker = async_sessionmaker(dbengine.get())
        async with async_session_maker() as session:
            stmt = (
                select(cls)
                .where(cls.token_endpoint.ilike(f"%{iss}%"))
                .order_by(cls.id.asc())
            )
            result = await session.execute(stmt)
            response = result.scalar()
        return response

    @classmethod
    async def get_auth_id_type_config(cls, id: int = None, iss: str = None):
        iss_id = id if id else iss
        id_type_config = auth_id_type_config_cache.get().get(iss_id, None)
        if not id_type_config:
            ap = None
            if id:
                ap = await cls.get_by_id(id)
            elif iss:
                ap = await cls.get_auth_provider_from_iss(iss)

            if ap and ap.g2p_id_type:
                id_type_config = {
                    "g2p_id_type": ap.g2p_id_type,
                    "token_map": ap.token_map,
                    "date_format": ap.date_format,
                    "auth_provider_id": ap.id,
                }
                auth_id_type_config_cache.get()[iss_id] = id_type_config
        return id_type_config

    def map_auth_provider_to_login_provider(self) -> LoginProvider:
        response_type = "token"
        if self.flow == "oidc_implicit":
            response_type = "id_token token"
        elif self.flow == "oidc_auth_code":
            response_type = "code"

        type = LoginProviderTypes.oauth2_auth_code

        return LoginProvider(
            id=self.id,
            name=self.name,
            type=type,
            description=self.name,
            login_button_text=self.body or "",
            login_button_image_url=self.image_icon_url or "",
            authorization_parameters=OauthProviderParameters(
                authorize_endpoint=self.auth_endpoint,
                token_endpoint=self.token_endpoint,
                validate_endpoint=self.validation_endpoint or "",
                jwks_endpoint=self.jwks_uri or "",
                client_id=self.client_id,
                client_secret=self.client_secret,
                client_assertion_type=OauthClientAssertionType[
                    "client_secret"
                    if self.client_authentication_method.startswith("client_secret")
                    else self.client_authentication_method
                ],
                client_assertion_jwk=base64.b64decode(self.client_private_key)
                if self.client_private_key
                else None,
                client_assertion_jwk_aud=self.jwt_assertion_aud,
                response_type=response_type,
                redirect_uri=self.g2p_portal_oauth_callback_url or "",
                scope=self.scope,
                enable_pkce=self.enable_pkce,
                code_verifier=self.code_verifier,
                extra_authorize_parameters=orjson.loads(
                    self.extra_authorize_params or "{}"
                ),
            ).model_dump(),
            active=True,
        )

    @classmethod
    def map_validation_response(cls, req: dict, mapping: str = None):
        res = {}
        mapping = mapping.strip() if mapping else ""
        if mapping:
            if mapping.endswith("*:*"):
                res = req
            for pair in mapping.split(" "):
                from_key, to_key = (k.strip() for k in pair.split(":", 1))
                res[to_key] = req.get(from_key, "")
        return res
