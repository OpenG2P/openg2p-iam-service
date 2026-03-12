from fastapi import Depends, Request
from openg2p_iam_core.schemas import AuthCredentials, AuthPrincipal
from openg2p_fastapi_common.errors.http_exceptions import ForbiddenError

from ..dependencies import JwtBearerAuth
from .implementations import (
    BeneficiaryAuthAdapter,
    StaffAuthAdapter,
    AgentAuthAdapter,
)


async def _authenticate_user(
    request: Request,
    auth_credentials: AuthCredentials,
) -> AuthPrincipal:
    claims = auth_credentials.model_dump()
    user_type = claims.get("user_type") or claims.get("userType")

    if user_type == "beneficiary":
        strategy = BeneficiaryAuthAdapter()
    elif user_type == "staff":
        strategy = StaffAuthAdapter()
    elif user_type == "agent":
        strategy = AgentAuthAdapter()
    else:
        # Fallback: infer from roles for providers that omit user_type.
        realm_roles = set((claims.get("realm_access") or {}).get("roles") or [])
        resource_access = claims.get("resource_access") or {}
        role_set = set(realm_roles)
        for value in resource_access.values():
            role_set.update((value or {}).get("roles") or [])

        if "staff" in role_set:
            strategy = StaffAuthAdapter()
        elif "agent" in role_set:
            strategy = AgentAuthAdapter()
        elif "beneficiary" in role_set:
            strategy = BeneficiaryAuthAdapter()
        else:
            raise ForbiddenError(message="Forbidden. Cannot infer auth strategy.")

    return await strategy.adapt(request, auth_credentials)


class AuthFactory:
    """
    Generic Factory-based dependency that accepts user type.

    Usage:
        @app.get("/profile")
        async def get_profile(auth: AuthCredentials = Depends(AuthFactory())):
            return {"user_id": auth.sub}
    """

    async def __call__(
        self,
        request: Request,
        auth_credentials: AuthCredentials = Depends(JwtBearerAuth()),
    ) -> AuthPrincipal:
        return await _authenticate_user(request, auth_credentials)
