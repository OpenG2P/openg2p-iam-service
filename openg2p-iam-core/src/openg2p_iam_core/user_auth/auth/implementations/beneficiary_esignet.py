from fastapi import Request
from openg2p_iam_core.schemas import AuthCredentials
from openg2p_fastapi_common.errors.http_exceptions import ForbiddenError

from ..interface import AuthInterface


class BeneficiaryEsignetAuth(AuthInterface):
    """Handles beneficiary authentication via Esignet/other OIDC."""

    async def authenticate(
        self, request: Request, auth_credentials: AuthCredentials
    ) -> AuthCredentials:
        claims = auth_credentials.model_dump()

        user_type = claims.get("user_type") or claims.get("userType")
        if not user_type:
            # Esignet/Google-like providers may not emit user_type.
            realm_roles = set((claims.get("realm_access") or {}).get("roles") or [])
            resource_access = claims.get("resource_access") or {}
            provider_roles = set()
            for value in resource_access.values():
                provider_roles.update((value or {}).get("roles") or [])
            if "beneficiary" in (realm_roles | provider_roles):
                claims["user_type"] = "beneficiary"
                user_type = "beneficiary"

        if user_type != "beneficiary":
            raise ForbiddenError(message="Forbidden. Invalid userType.")

        return AuthCredentials.model_validate(claims)
