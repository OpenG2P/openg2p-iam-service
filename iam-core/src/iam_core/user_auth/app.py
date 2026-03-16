# ruff: noqa: E402

from .config import Settings

_config = Settings.get_config()

from openg2p_fastapi_common.app import Initializer as BaseInitializer

from openg2p_iam_core.services.provider_repository import ProviderRepository
from openg2p_iam_core.services.auth_transaction_store import AuthTransactionStore
from openg2p_iam_core.services.redis_auth_transaction_store import RedisAuthTransactionStore
from openg2p_iam_core.services.token_validator_service import TokenValidatorService
from openg2p_iam_core.user_auth.adapters.oidc_base import OIDCBase
from openg2p_iam_core.user_auth.adapters.implementations.keycloak_adapter import KeycloakAdapter
from openg2p_iam_core.user_auth.adapters.implementations.esignet_adapter import EsignetAdapter
from openg2p_iam_core.user_auth.adapters.registry import AdapterFactory
from openg2p_iam_core.partner_auth.jwt_validation_helper import JWTValidationHelper


class Initializer(BaseInitializer):
    def initialize(self, **kwargs):
        super().initialize()

        # Adapters
        OIDCBase()
        KeycloakAdapter()
        EsignetAdapter()
        AdapterFactory()

        # Services
        ProviderRepository()
        AuthTransactionStore()
        if getattr(_config, "auth_transaction_store_backend", "memory") == "redis":
            RedisAuthTransactionStore()
        TokenValidatorService()
        JWTValidationHelper()
