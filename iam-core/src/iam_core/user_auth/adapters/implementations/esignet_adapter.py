from typing import Any

from iam_core.models import LoginProvider
from iam_core.user_auth.adapters.oidc_base import OIDCBase


class EsignetAdapter(OIDCBase):
    name = "esignet"

    def normalize_claims(
        self,
        claims: dict[str, Any],
        login_provider: LoginProvider,
    ) -> dict[str, Any]:
        normalized = dict(claims)

        # Some integrations send provider/realm roles only in nested claims.
        if "roles" not in normalized:
            realm_roles = ((normalized.get("realm_access") or {}).get("roles")) or []
            if realm_roles:
                normalized["roles"] = realm_roles
        return normalized

    def validate_claims(
        self,
        claims: dict[str, Any],
        login_provider: LoginProvider,
    ) -> None:
        # Keep strictness minimal and leave route-level authorization to dependencies.
        if not claims.get("sub"):
            raise ValueError("Missing required 'sub' claim for e-Signet user.")
