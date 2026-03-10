from fastapi import Depends, Request
from openg2p_iam_core.schemas import AuthCredentials

from ..dependencies import JwtBearerAuth
from .implementations import (
    BeneficiaryEsignetAuth,
    StaffKeycloakAuth,
    AgentKeycloakAuth,
)


async def _authenticate_user(
    request: Request,
    auth_credentials: AuthCredentials,
) -> AuthCredentials:
    claims = auth_credentials.model_dump()
    user_type = claims.get("user_type") or claims.get("userType")

    if user_type == "beneficiary":
        strategy = BeneficiaryEsignetAuth()
    elif user_type == "staff":
        strategy = StaffKeycloakAuth()
    elif user_type == "agent":
        strategy = AgentKeycloakAuth()
    else:
        raise ValueError(f"No strategy found for user_type: {user_type}")

    return await strategy.authenticate(request, auth_credentials)


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
    ) -> AuthCredentials:
        return await _authenticate_user(request, auth_credentials)
