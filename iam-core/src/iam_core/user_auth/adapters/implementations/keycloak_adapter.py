from typing import Any

from openg2p_fastapi_common.service import BaseService

from openg2p_iam_core.models import LoginProvider
from openg2p_iam_core.user_auth.adapters.oidc_base import OIDCBase


class KeycloakAdapter(BaseService, OIDCBase):
    name = "keycloak"

    def normalize_claims(
        self,
        claims: dict[str, Any],
        login_provider: LoginProvider,
    ) -> dict[str, Any]:
        normalized = dict(claims)

        realm_roles = set(((normalized.get("realm_access") or {}).get("roles")) or [])
        resource_access = normalized.get("resource_access") or {}
        resource_roles = set()
        for value in resource_access.values():
            resource_roles.update((value or {}).get("roles") or [])
        all_roles = sorted(realm_roles | resource_roles)

        if "roles" not in normalized and all_roles:
            normalized["roles"] = all_roles

        if not normalized.get("user_type"):
            # Fallback user_type inference from common realm roles.
            for value in ("staff", "agent", "beneficiary"):
                if value in realm_roles or value in resource_roles:
                    normalized["user_type"] = value
                    break

        return normalized

    def validate_claims(
        self,
        claims: dict[str, Any],
        login_provider: LoginProvider,
    ) -> None:
        if not claims.get("sub"):
            raise ValueError("Missing required 'sub' claim for Keycloak user.")
