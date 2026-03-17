from openg2p_fastapi_common.service import BaseService

from iam_core.models import LoginProvider
from iam_core.user_auth.adapters.implementations.esignet_adapter import EsignetAdapter
from iam_core.user_auth.adapters.implementations.keycloak_adapter import KeycloakAdapter
from iam_core.user_auth.adapters.oidc_base import OIDCBase


class AdapterFactory(BaseService):
    """Resolves OIDC adapters by provider name. Use get_component() for singleton."""

    def __init__(self):
        super().__init__()
        self._adapters = self._get_adapter_map()

    def _get_adapter_map(self):
        return {
            "default_oidc": OIDCBase.get_component(),
            "keycloak": KeycloakAdapter.get_component(),
            "esignet": EsignetAdapter.get_component(),
            "mosip_esignet": EsignetAdapter.get_component(),
        }

    def get(self, adapter_name: str | None):
        key = (adapter_name or "default_oidc").strip().lower()
        return self._adapters.get(key, self._adapters["default_oidc"])

    def resolve_for_provider(self, login_provider: LoginProvider):
        return self.get(getattr(login_provider, "adapter_name", None))
