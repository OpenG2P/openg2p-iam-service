from openg2p_iam_core.models import LoginProvider
from openg2p_iam_core.user_auth.adapters.implementations.esignet_adapter import EsignetAdapter
from openg2p_iam_core.user_auth.adapters.implementations.keycloak_adapter import KeycloakAdapter
from openg2p_iam_core.user_auth.adapters.oidc_base import OIDCBase


class AdapterRegistry: #TODO: Call this adapter factory
    def __init__(self):
        default = OIDCBase()
        self._adapters = { # TODO: Refactor
            "default_oidc": default,
            "keycloak": KeycloakAdapter(), #TODO: get_component()
            "esignet": EsignetAdapter(),
            "mosip_esignet": EsignetAdapter(),
        }

    def get(self, adapter_name: str | None):
        key = (adapter_name or "default_oidc").strip().lower()
        return self._adapters.get(key, self._adapters["default_oidc"])

    def resolve_for_provider(self, login_provider: LoginProvider):
        return self.get(getattr(login_provider, "adapter_name", None))
