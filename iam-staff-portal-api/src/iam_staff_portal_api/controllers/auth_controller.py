from typing import Annotated, List

from fastapi import Depends, Request, Response
from fastapi.responses import RedirectResponse
from datetime import datetime, timedelta, timezone
from openg2p_fastapi_common.context import dbengine
from openg2p_fastapi_common.controller import BaseController
from iam_core.schemas import (
    AuthPrincipal,
    LoginProviderHttpResponse,
    StartAuthTransactionResponse,
)
from iam_core.services import AuthService
from iam_core.user_auth.dependencies import auth_principal, require_user_type
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from ..config import Settings
from ..models import (
    StaffApplicationAction,
    StaffPortalApplication,
    StaffRole,
    StaffRoleAction,
)
from ..schemas import ApplicationActionResponse, StaffPortalApplicationResponse

_config = Settings.get_config(strict=False)


class AuthController(BaseController):
    user_type = "staff"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.router.prefix += "/auth"
        self.router.tags += ["/auth"]
        self.auth_service = AuthService(user_type=self.user_type)

        self.router.add_api_route("/get_user_profile", self.get_user_profile, methods=["GET"])
        self.router.add_api_route("/logout", self.logout, methods=["POST"])
        self.router.add_api_route(
            "/get_login_providers",
            self.get_login_providers,
            responses={200: {"model": LoginProviderHttpResponse}},
            methods=["GET"],
        )
        self.router.add_api_route(
            "/start_authentication_transaction",
            self.start_authentication_transaction,
            responses={200: {"model": StartAuthTransactionResponse}},
            methods=["POST"],
        )
        self.router.add_api_route("/callback", self.oauth_callback, methods=["GET"])
        self.router.add_api_route(
            "/get_staff_portal_applications",
            self.get_staff_portal_applications,
            response_model=List[StaffPortalApplicationResponse],
            methods=["GET"],
        )
        self.router.add_api_route(
            "/get_application_actions_for_user",
            self.get_application_actions_for_user,
            response_model=List[ApplicationActionResponse],
            methods=["GET"],
        )
        self.router.add_api_route(
            "/get_provider_by_issuer",
            self.get_provider_by_issuer,
            methods=["GET"],
        )

    async def get_user_profile(
        self,
        auth: Annotated[
            AuthPrincipal,
            Depends(require_user_type("staff", auth_dependency=auth_principal)),
        ],
    ):
        return auth.model_dump(exclude={"credentials"})

    async def logout(self, response: Response):
        response.delete_cookie(
            "X-Access-Token",
            path=_config.auth_cookie_path,
            domain=_config.auth_cookie_domain,
        )
        response.delete_cookie(
            "X-ID-Token",
            path=_config.auth_cookie_path,
            domain=_config.auth_cookie_domain,
        )

    async def get_login_providers(self):
        return await self.auth_service.get_login_providers()

    async def start_authentication_transaction(self, id: int, redirect_uri: str = "/"):
        return await self.auth_service.start_authentication_transaction(
            provider_id=id,
            redirect_uri=redirect_uri,
        )

    async def oauth_callback(self, request: Request):
        result = await self.auth_service.complete_authentication_transaction(
            state_value=request.query_params.get("state"),
            code=request.query_params.get("code"),
        )
        token_response = result["token_response"]
        redirect_uri = result["redirect_uri"]
        expires_in = None
        if _config.auth_cookie_set_expires:
            seconds = token_response.get("expires_in")
            if seconds:
                expires_in = datetime.now(tz=timezone.utc) + timedelta(seconds=seconds)

        response = RedirectResponse(redirect_uri)
        response.set_cookie(
            "X-Access-Token",
            token_response["access_token"],
            max_age=_config.auth_cookie_max_age,
            expires=expires_in,
            path=_config.auth_cookie_path,
            domain=_config.auth_cookie_domain,
            httponly=_config.auth_cookie_httponly,
            secure=_config.auth_cookie_secure,
        )
        response.set_cookie(
            "X-ID-Token",
            token_response["id_token"],
            max_age=_config.auth_cookie_max_age,
            expires=expires_in,
            path=_config.auth_cookie_path,
            domain=_config.auth_cookie_domain,
            httponly=_config.auth_cookie_httponly,
            secure=_config.auth_cookie_secure,
        )
        return response

    async def get_staff_portal_applications(
        self,
        auth: Annotated[
            AuthPrincipal,
            Depends(require_user_type("staff", auth_dependency=auth_principal)),
        ],
    ) -> List[StaffPortalApplicationResponse]:
        client_roles = auth.client_roles or {}
        allowed_mnemonics = list(client_roles.keys())

        async_session = async_sessionmaker(dbengine.get())
        async with async_session() as session:
            stmt = (
                select(StaffPortalApplication)
                .where(StaffPortalApplication.active == True)
                .order_by(
                    StaffPortalApplication.order.asc().nullslast(),
                    StaffPortalApplication.id.asc(),
                )
            )
            apps = (await session.execute(stmt)).scalars().all()

        return [
            {
                "id": app.id,
                "application_mnemonic": app.application_mnemonic,
                "application_description": app.application_description,
                "icon_base64": app.icon_base64,
                "width": app.width,
                "order": app.order,
                "disabled": app.application_mnemonic not in allowed_mnemonics,
                "application_url": (
                    app.application_url
                    if app.application_mnemonic in allowed_mnemonics
                    else None
                ),
            }
            for app in apps
        ]

    async def get_application_actions_for_user(
        self,
        auth: Annotated[
            AuthPrincipal,
            Depends(require_user_type("staff", auth_dependency=auth_principal)),
        ],
    ) -> List[ApplicationActionResponse]:
        client_roles = auth.client_roles or {}
        if not client_roles:
            return []

        result = []
        async_session = async_sessionmaker(dbengine.get())
        async with async_session() as session:
            for client_id, roles in client_roles.items():
                # Find the application by mnemonic (= Keycloak client_id)
                stmt = select(StaffPortalApplication).where(
                    StaffPortalApplication.application_mnemonic == client_id,
                    StaffPortalApplication.active == True,  # noqa: E712
                )
                app_row = (await session.execute(stmt)).scalars().first()
                if not app_row:
                    continue

                # Find role IDs matching the token roles for this application
                role_stmt = select(StaffRole).where(
                    StaffRole.application_id == app_row.id,
                    StaffRole.role_mnemonic.in_(roles),
                    StaffRole.active == True,  # noqa: E712
                )
                role_rows = (await session.execute(role_stmt)).scalars().all()
                role_ids = [r.id for r in role_rows]

                if not role_ids:
                    continue

                # Get action IDs mapped to those roles
                mapping_stmt = select(StaffRoleAction.action_id).where(
                    StaffRoleAction.role_id.in_(role_ids),
                    StaffRoleAction.active == True,  # noqa: E712
                )
                action_ids = (
                    (await session.execute(mapping_stmt)).scalars().all()
                )

                if not action_ids:
                    continue

                # Get the action details
                action_stmt = select(StaffApplicationAction).where(
                    StaffApplicationAction.id.in_(action_ids),
                    StaffApplicationAction.active == True,  # noqa: E712
                )
                action_rows = (
                    (await session.execute(action_stmt)).scalars().all()
                )

                actions = sorted(
                    set(a.action_mnemonic for a in action_rows)
                )

                if actions:
                    result.append(
                        {
                            "application_id": app_row.id,
                            "application_mnemonic": app_row.application_mnemonic,
                            "actions": actions,
                        }
                    )

        return result

    async def get_provider_by_issuer(self, issuer: str):
        return await self.auth_service.get_provider_by_issuer(issuer)
