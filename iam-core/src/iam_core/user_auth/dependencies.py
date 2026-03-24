from typing import Any, Annotated, Callable

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from openg2p_fastapi_common.errors.http_exceptions import (
    ForbiddenError,
    UnauthorizedError,
)

from iam_core.schemas import AuthCredentials, AuthPrincipal
from iam_core.services.token_validator_service import TokenValidatorService

from .config import ApiAuthSettings, Settings

_config = Settings.get_config(strict=False)


class JwtBearerAuth(HTTPBearer):
    async def __call__(self, request: Request) -> HTTPAuthorizationCredentials | None:
        config_dict = _config.model_dump()
        if not config_dict.get("auth_enabled", None):
            return None

        api_call_name = str(request.scope["route"].name)

        api_auth_settings = ApiAuthSettings.model_validate(
            config_dict.get("auth_api_" + api_call_name, {})
        )

        jwt_token = request.headers.get("Authorization", None) or request.cookies.get(
            "X-Access-Token", None
        )
        jwt_id_token = request.cookies.get("X-ID-Token", None)
        if jwt_token:
            jwt_token = jwt_token.removeprefix("Bearer ")

        if not jwt_token:
            raise UnauthorizedError()

        token_validator = TokenValidatorService.get_component()
        return await token_validator.validate(
            jwt_token=jwt_token,
            jwt_id_token=jwt_id_token,
            api_auth_settings=api_auth_settings,
        )


def _claims_from_auth(auth: Any) -> dict:
    if hasattr(auth, "model_dump"):
        return auth.model_dump()
    if isinstance(auth, dict):
        return auth
    return {}


def _extract_client_roles(claims: dict) -> dict[str, list[str]] | None:
    resource_access = claims.get("resource_access") or {}
    if not resource_access:
        return None
    result = {}
    for client, value in resource_access.items():
        roles = (value or {}).get("roles") or []
        if roles:
            result[client] = sorted(roles)
    return result or None


def _resolve_user_type(claims: dict) -> str | None:
    return claims.get("user_type") or claims.get("userType")


async def auth_principal(
    auth: Annotated[AuthCredentials, Depends(JwtBearerAuth())],
) -> AuthPrincipal:
    if auth is None:
        return AuthPrincipal(credentials="")
    claims = auth.model_dump()
    return AuthPrincipal(
        scheme=auth.scheme,
        name=auth.name,
        credentials=auth.credentials,
        sub=claims.get("sub"),
        user_type=_resolve_user_type(claims),
        aud=claims.get("aud"),
        client_roles=_extract_client_roles(claims),
    )


def has_claim(
    name: str,
    auth_dependency: Callable | None = None,
):
    async def dependency(
        auth: Annotated[Any, Depends(auth_dependency or JwtBearerAuth())],
    ):
        claims = _claims_from_auth(auth)
        if claims.get(name) is None:
            raise ForbiddenError(message=f"Forbidden. Missing claim: {name}.")
        return auth

    return dependency


def claim_equals(
    name: str,
    value: str,
    auth_dependency: Callable | None = None,
):
    async def dependency(
        auth: Annotated[Any, Depends(auth_dependency or JwtBearerAuth())],
    ):
        claims = _claims_from_auth(auth)
        if claims.get(name) != value:
            raise ForbiddenError(message=f"Forbidden. Claim {name} mismatch.")
        return auth

    return dependency


def claim_in(
    name: str,
    allowed: set[str],
    auth_dependency: Callable | None = None,
):
    async def dependency(
        auth: Annotated[Any, Depends(auth_dependency or JwtBearerAuth())],
    ):
        claims = _claims_from_auth(auth)
        claim_value = claims.get(name)
        if isinstance(claim_value, str):
            values = {claim_value}
        elif isinstance(claim_value, list):
            values = set(claim_value)
        else:
            values = set()
        if not values.intersection(allowed):
            raise ForbiddenError(message=f"Forbidden. Claim {name} not allowed.")
        return auth

    return dependency


def require_user_type(
    expected: str,
    auth_dependency: Callable | None = None,
):
    async def dependency(
        auth: Annotated[Any, Depends(auth_dependency or JwtBearerAuth())],
    ):
        claims = _claims_from_auth(auth)
        print("Claims from auth: ", claims)
        user_type = claims.get("user_type") or claims.get("userType")
        print("User type: ", user_type, " | Expected: ", expected)
        if user_type != expected:
            raise ForbiddenError(message="Forbidden. Invalid userType.")
        return auth

    return dependency


def check_resource_access(
    allowed_roles: set[str],
    client_id: str | None = None,
    auth_dependency: Callable | None = None,
):
    """Check that the user has at least one of the allowed roles in resource_access.

    Args:
        allowed_roles: Set of role/privilege/action names to check for.
        client_id: If given, only check roles under this specific client.
                   If None, check across all clients in resource_access.
        auth_dependency: Upstream dependency. Defaults to auth_principal.
    """

    async def dependency(
        auth: Annotated[Any, Depends(auth_dependency or auth_principal)],
    ):
        claims = _claims_from_auth(auth)
        client_roles = claims.get("client_roles") or {}

        if client_id:
            user_roles = set(client_roles.get(client_id, []))
        else:
            user_roles = set()
            for roles in client_roles.values():
                user_roles.update(roles)

        if not user_roles.intersection(allowed_roles):
            raise ForbiddenError(message="Forbidden. Insufficient resource_access roles.")
        return auth

    return dependency
