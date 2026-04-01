from typing import Annotated, List, Optional

from fastapi import Depends
from fastapi_cache.decorator import cache
from iam_core.schemas import AuthPrincipal
from iam_core.user_auth.dependencies import auth_principal, require_user_type
from openg2p_fastapi_common.context import dbengine
from openg2p_fastapi_common.controller import BaseController
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from ..cache import role_cache_key
from ..config import Settings
from ..models import (
    StaffApplicationPermission,
    StaffPortalApplication,
    StaffRole,
    StaffRolePermission,
)
from ..schemas import (
    ApplicationPermissionResponse,
    GetPermissionsForRolesRequest,
    PermissionsResponse,
    StaffPortalApplicationResponse,
)


_config = Settings.get_config(strict=False)

class UserAccessController(BaseController):
    '''
    Controller for managing user access to staff portal applications and their associated permissions.
    '''
    user_type = "staff"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.router.prefix += "/user-access"
        self.router.tags += ["/user-access"]

        self.router.add_api_route(
            "/get_staff_portal_applications",
            self.get_staff_portal_applications,
            response_model=List[StaffPortalApplicationResponse],
            methods=["GET"],
        )
        self.router.add_api_route(
            "/get_application_permissions_for_user",
            self.get_application_permissions_for_user,
            response_model=List[ApplicationPermissionResponse],
            methods=["GET"],
        )
        self.router.add_api_route(
            "/get_permissions_for_roles",
            self.get_permissions_for_roles,
            response_model=PermissionsResponse,
            methods=["POST"],
        )

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
                .where(StaffPortalApplication.active.is_(True))
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

    async def get_application_permissions_for_user(
        self,
        auth: Annotated[
            AuthPrincipal,
            Depends(require_user_type("staff", auth_dependency=auth_principal)),
        ],
        application_mnemonic: Optional[str] = None,
    ) -> List[ApplicationPermissionResponse]:
        client_roles = auth.client_roles or {}
        if not client_roles:
            return []

        if application_mnemonic:
            roles = client_roles.get(application_mnemonic)
            if not roles:
                return []
            client_roles_items = [(application_mnemonic, roles)]
        else:
            client_roles_items = client_roles.items()

        result = []
        async_session = async_sessionmaker(dbengine.get())
        async with async_session() as session:
            for client_id, roles in client_roles_items:
                # Find the application by mnemonic (= Keycloak client_id).
                stmt = select(StaffPortalApplication).where(
                    StaffPortalApplication.application_mnemonic == client_id,
                    StaffPortalApplication.active == True,  # noqa: E712
                )
                app_row = (await session.execute(stmt)).scalars().first()
                if not app_row:
                    continue

                # Find role IDs matching the token roles for this application.
                role_stmt = select(StaffRole).where(
                    StaffRole.application_id == app_row.id,
                    StaffRole.role_mnemonic.in_(roles),
                    StaffRole.active == True,  # noqa: E712
                )
                role_rows = (await session.execute(role_stmt)).scalars().all()
                role_ids = [r.id for r in role_rows]

                if not role_ids:
                    continue

                # Get permission IDs mapped to those roles.
                mapping_stmt = select(StaffRolePermission.permission_id).where(
                    StaffRolePermission.role_id.in_(role_ids),
                    StaffRolePermission.active == True,  # noqa: E712
                )
                permission_ids = (await session.execute(mapping_stmt)).scalars().all()

                if not permission_ids:
                    continue

                # Get the permission details.
                permission_stmt = select(StaffApplicationPermission).where(
                    StaffApplicationPermission.id.in_(permission_ids),
                    StaffApplicationPermission.active == True,  # noqa: E712
                )
                permission_rows = (await session.execute(permission_stmt)).scalars().all()

                permissions = sorted(set(p.permission_mnemonic for p in permission_rows))

                if permissions:
                    result.append(
                        {
                            "application_id": app_row.id,
                            "application_mnemonic": app_row.application_mnemonic,
                            "permissions": permissions,
                        }
                    )

        return result

    async def get_permissions_for_roles(
        self,
        request: GetPermissionsForRolesRequest,
    ) -> PermissionsResponse:
        permissions: List[str] = []

        for role_mnemonic in request.role_mnemonics:
            permissions.extend(
                await self.get_permission_mnemonics_for_role(role_mnemonic)
            )

        return PermissionsResponse(permissions=sorted(set(permissions)))

    @cache(expire=_config.cache_expire_seconds, key_builder=role_cache_key)
    async def get_permission_mnemonics_for_role(
        self,
        role_mnemonic: str,
    ) -> List[str]:
        async_session = async_sessionmaker(dbengine.get())
        async with async_session() as session:
            role_stmt = select(StaffRole).where(
                StaffRole.role_mnemonic == role_mnemonic,
                StaffRole.active == True,  # noqa: E712
            )
            role = (await session.execute(role_stmt)).scalars().first()

            if not role:
                return []

            mapping_stmt = select(StaffRolePermission.permission_id).where(
                StaffRolePermission.role_id == role.id,
                StaffRolePermission.active == True,  # noqa: E712
            )
            permission_ids = (await session.execute(mapping_stmt)).scalars().all()

            if not permission_ids:
                return []

            permission_stmt = select(StaffApplicationPermission.permission_mnemonic).where(
                StaffApplicationPermission.id.in_(permission_ids),
                StaffApplicationPermission.active == True,  # noqa: E712
            )
            return (await session.execute(permission_stmt)).scalars().all()
