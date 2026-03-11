from fastapi import Request
from openg2p_iam_core.schemas import AuthCredentials
from openg2p_fastapi_common.errors.http_exceptions import ForbiddenError

from ..interface import AuthInterface


class StaffKeycloakAuth(AuthInterface):
    """Handles staff authentication via Keycloak."""

    async def authenticate(
        self, request: Request, auth_credentials: AuthCredentials
    ) -> AuthCredentials:
        claims = auth_credentials.model_dump()

        user_type = claims.get("user_type") or claims.get("userType")
        if user_type != "staff":
            raise ForbiddenError(message="Forbidden. Invalid userType.")

        realm_roles = set((claims.get("realm_access") or {}).get("roles") or [])
        client_roles = set(
            ((claims.get("resource_access") or {}).get("staff-portal") or {}).get(
                "roles"
            )
            or []
        )
        effective_roles = realm_roles | client_roles

        if "staff" not in effective_roles:
            raise ForbiddenError(message="Forbidden. Missing required role(s).")

        return auth_credentials
