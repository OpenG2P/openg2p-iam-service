from collections.abc import Callable
from typing import Any

from fastapi import Request
from openg2p_fastapi_common.errors.base_exception import BaseAppException
from openg2p_fastapi_common.errors.http_exceptions import ForbiddenError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Match

from .dependencies import JwtBearerAuth, auth_principal, enforce_resource_access
from .helpers import user_auth_error_response, get_required_permissions as default_get_required_permissions

class AuthorizationService(BaseHTTPMiddleware):
    """Reusable IAM authorization middleware.

    Subclasses may override ``get_required_permissions`` or pass a
    ``required_permissions_resolver`` callback.
    """

    def __init__(
        self,
        app,
        *,
        client_id: str | None = None,
        allow_by_default: bool = True,
        state_key: str = "auth_principal",
        required_permissions_resolver: Callable[[Request, Any], set[str]] | None = None,
    ):
        super().__init__(app)
        self._auth_scheme = JwtBearerAuth()
        self._client_id = client_id
        self._allow_by_default = allow_by_default
        self._state_key = state_key
        self._required_permissions_resolver = required_permissions_resolver

    def get_required_permissions(self, request: Request, route: Any) -> set[str]:
        if self._required_permissions_resolver is not None:
            roles = self._required_permissions_resolver(request, route) or set()
            return {str(role) for role in roles}
        return default_get_required_permissions(getattr(route, "endpoint", None))

    def get_client_id(self, request: Request) -> str | None:
        return self._client_id

    def _match_route(self, request: Request) -> Any | None:
        router = getattr(request.app, "router", None)
        routes = list(getattr(router, "routes", []))
        for route in routes:
            match, _ = route.matches(request.scope)
            if match == Match.FULL:
                return route
        return None

    async def dispatch(self, request: Request, call_next):
        try:
            matched_route = self._match_route(request)
            if matched_route is None:
                return await call_next(request)

            required_roles = self.get_required_permissions(request, matched_route)
            if not required_roles and self._allow_by_default:
                return await call_next(request)

            request.scope["route"] = matched_route

            client_id = (self.get_client_id(request) or "").strip()
            if required_roles and not client_id:
                raise ForbiddenError(message="Forbidden. keycloak_client_id is not configured.")

            auth_credentials = await self._auth_scheme(request)
            principal = await auth_principal(auth_credentials)

            if required_roles:
                enforce_resource_access(
                    auth=principal,
                    allowed_roles=required_roles,
                    client_id=client_id,
                )

            setattr(request.state, self._state_key, principal)
            return await call_next(request)
        except BaseAppException as exc:
            return user_auth_error_response(request, exc)
