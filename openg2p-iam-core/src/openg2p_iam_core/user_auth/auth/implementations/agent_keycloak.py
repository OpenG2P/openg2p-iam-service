from fastapi import Request
from openg2p_iam_core.schemas import AuthCredentials
from openg2p_fastapi_common.errors.http_exceptions import ForbiddenError

from ..interface import AuthInterface


class AgentKeycloakAuth(AuthInterface):
    """Handles agent authentication via Keycloak."""

    async def authenticate(
        self, request: Request, auth_credentials: AuthCredentials
    ) -> AuthCredentials:
        claims = auth_credentials.model_dump()

        user_type = claims.get("user_type") or claims.get("userType")
        realm_roles = set((claims.get("realm_access") or {}).get("roles") or [])
        client_roles = set(
            ((claims.get("resource_access") or {}).get("agent-portal") or {}).get(
                "roles"
            )
            or []
        )
        effective_roles = realm_roles | client_roles

        if not user_type and "agent" in effective_roles:
            claims["user_type"] = "agent"
            user_type = "agent"

        if user_type != "agent":
            raise ForbiddenError(message="Forbidden. Invalid userType.")

        if "agent" not in effective_roles:
            raise ForbiddenError(message="Forbidden. Missing required role(s).")

        return AuthCredentials.model_validate(claims)
