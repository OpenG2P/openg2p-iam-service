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
        if user_type != "beneficiary":
            raise ForbiddenError(message="Forbidden. Invalid userType.")

        return auth_credentials
