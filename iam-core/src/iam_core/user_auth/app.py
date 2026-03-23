# ruff: noqa: E402

from .config import Settings

_config = Settings.get_config()

from openg2p_fastapi_common.app import Initializer as BaseInitializer

from iam_core.services.provider_repository import ProviderRepository
from iam_core.services.auth_transaction_store import AuthTransactionStore
from iam_core.services.redis_auth_transaction_store import RedisAuthTransactionStore
from iam_core.services.token_validator_service import TokenValidatorService
from iam_core.user_auth.adapters.oidc_base import OIDCBase
from iam_core.user_auth.adapters.implementations.keycloak_adapter import KeycloakAdapter
from iam_core.user_auth.adapters.implementations.esignet_adapter import EsignetAdapter
from iam_core.user_auth.adapters.registry import AdapterFactory
from iam_core.partner_auth.jwt_validation_helper import JWTValidationHelper


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
        RedisAuthTransactionStore()
        TokenValidatorService()
        JWTValidationHelper()
