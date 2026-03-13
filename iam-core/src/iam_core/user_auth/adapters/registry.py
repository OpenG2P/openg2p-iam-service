from openg2p_iam_core.models import LoginProvider
from openg2p_iam_core.user_auth.adapters.default_oidc_adapter import DefaultOidcAdapter
from openg2p_iam_core.user_auth.adapters.esignet_adapter import EsignetAdapter
from openg2p_iam_core.user_auth.adapters.keycloak_adapter import KeycloakAdapter


class AdapterRegistry:
    def __init__(self):
        default = DefaultOidcAdapter()
        self._adapters = {
            "default_oidc": default,
            "keycloak": KeycloakAdapter(),
            "esignet": EsignetAdapter(),
            "mosip_esignet": EsignetAdapter(),
        }

    def get(self, adapter_name: str | None):
        key = (adapter_name or "default_oidc").strip().lower()
        return self._adapters.get(key, self._adapters["default_oidc"])

    def resolve_for_provider(self, login_provider: LoginProvider):
        return self.get(getattr(login_provider, "adapter_name", None))
