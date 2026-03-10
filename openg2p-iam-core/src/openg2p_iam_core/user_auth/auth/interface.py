from fastapi import Request
from openg2p_iam_core.schemas import AuthCredentials

from ..dependencies import JwtBearerAuth


class AuthInterface(JwtBearerAuth):
    """Base interface for authentication strategies."""

    async def authenticate(self, request: Request, auth_credentials: AuthCredentials) -> AuthCredentials:
        return auth_credentials

    async def __call__(self, request: Request) -> AuthCredentials:
        auth_credentials = await super().__call__(request)
        if not auth_credentials:
            return None

        return await self.authenticate(request, auth_credentials)
