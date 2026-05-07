import json
from typing import Any

from iam_core.models import LoginProvider
from iam_core.user_auth.adapters.oidc_base import OIDCBase


class EsignetAdapter(OIDCBase):
    name = "esignet"

    async def enrich_claims_from_userinfo(
        self,
        claims: dict[str, Any],
        *,
        login_provider: LoginProvider,
        access_token: str | None,
    ) -> dict[str, Any]:
        if not access_token:
            return claims
        try:
            userinfo = await self.get_oauth_validation_data(
                login_provider=login_provider,
                access_token=access_token,
            )
            if isinstance(userinfo, dict) and userinfo:
                merged = dict(claims)
                # userinfo takes precedence (e.g. individual_id)
                merged.update(userinfo)
                return merged
        except Exception:
            return claims
        return claims

    async def build_authorize_redirect(
        self,
        login_provider: LoginProvider,
        state: str,
        nonce: str,
        code_verifier: str,
        server_metadata: dict | None = None,
    ) -> tuple[str, str]:
        """
        eSignet integrations may use structured `claims` authorize param which must
        be JSON-encoded before URL encoding.
        """
        if login_provider.extra_authorize_params:
            try:
                extra = json.loads(login_provider.extra_authorize_params)
                claims = extra.get("claims")
                if isinstance(claims, (dict, list)):
                    extra["claims"] = json.dumps(claims, separators=(",", ":"))
                    old = login_provider.extra_authorize_params
                    login_provider.extra_authorize_params = json.dumps(extra)
                    try:
                        return await super().build_authorize_redirect(
                            login_provider=login_provider,
                            state=state,
                            nonce=nonce,
                            code_verifier=code_verifier,
                            server_metadata=server_metadata,
                        )
                    finally:
                        login_provider.extra_authorize_params = old
            except Exception:
                pass
        return await super().build_authorize_redirect(
            login_provider=login_provider,
            state=state,
            nonce=nonce,
            code_verifier=code_verifier,
            server_metadata=server_metadata,
        )

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
        if not (claims.get("individual_id") or claims.get("sub")):
            raise ValueError("Missing required subject claim ('individual_id' or 'sub') for e-Signet user.")

    def registrant_subject(
        self,
        claims: dict[str, Any],
        login_provider: LoginProvider,
    ) -> str | None:
        v = claims.get("individual_id") or claims.get("sub")
        return str(v) if v is not None else None
