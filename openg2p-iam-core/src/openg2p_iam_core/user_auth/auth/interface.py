from fastapi import Request
from openg2p_iam_core.schemas import AuthCredentials, AuthPrincipal

from ..dependencies import JwtBearerAuth


class TokenValidatorInterface:
    """Contract for raw JWT validation and claim extraction."""

    async def validate(self, request: Request) -> AuthCredentials | None:
        raise NotImplementedError()


class JwtTokenValidator(TokenValidatorInterface):
    def __init__(self, jwt_bearer_auth: JwtBearerAuth | None = None):
        self._jwt_bearer_auth = jwt_bearer_auth or JwtBearerAuth()

    async def validate(self, request: Request) -> AuthCredentials | None:
        return await self._jwt_bearer_auth(request)


class AuthAdapterInterface:
    """Contract for provider/category specific claim mapping."""

    async def adapt(
        self, request: Request, auth_credentials: AuthCredentials
    ) -> AuthPrincipal:
        raise NotImplementedError()

    async def __call__(self, request: Request) -> AuthPrincipal | None:
        raise NotImplementedError()


class AuthInterface(AuthAdapterInterface):
    """Backward-compatible auth strategy interface with adapter semantics."""

    def __init__(self, token_validator: TokenValidatorInterface | None = None):
        self._token_validator = token_validator or JwtTokenValidator()

    async def authenticate(
        self, request: Request, auth_credentials: AuthCredentials
    ) -> AuthCredentials:
        return auth_credentials

    @staticmethod
    def _extract_roles(claims: dict) -> list[str]:
        realm_roles = set((claims.get("realm_access") or {}).get("roles") or [])
        resource_access = claims.get("resource_access") or {}
        client_roles = set()
        for value in resource_access.values():
            client_roles.update((value or {}).get("roles") or [])
        return sorted(realm_roles | client_roles)

    @staticmethod
    def _resolve_user_type(claims: dict) -> str | None:
        return claims.get("user_type") or claims.get("userType")

    async def adapt(
        self, request: Request, auth_credentials: AuthCredentials
    ) -> AuthPrincipal:
        mapped_credentials = await self.authenticate(request, auth_credentials)
        claims = mapped_credentials.model_dump()
        return AuthPrincipal(
            scheme=mapped_credentials.scheme,
            credentials=mapped_credentials.credentials,
            iss=claims.get("iss"),
            sub=claims.get("sub"),
            user_type=self._resolve_user_type(claims),
            aud=claims.get("aud"),
            iat=claims.get("iat"),
            exp=claims.get("exp"),
            roles=self._extract_roles(claims),
            provider=claims.get("identity_provider") or claims.get("iss"),
            raw_claims=claims,
        )

    async def __call__(self, request: Request) -> AuthPrincipal | None:
        auth_credentials = await self._token_validator.validate(request)
        if not auth_credentials:
            return None

        return await self.adapt(request, auth_credentials)
