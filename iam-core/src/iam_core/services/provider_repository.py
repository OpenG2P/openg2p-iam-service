import logging
import time

from openg2p_fastapi_common.service import BaseService

from iam_core.models import LoginProvider
from iam_core.user_auth.config import ConfigLoginProvider, Settings

_CACHE_TTL_SECONDS = 60
_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class ProviderRepository(BaseService):
    def __init__(self):
        super().__init__()
        self._by_id_cache: dict[int, tuple[LoginProvider, float]] = {}

    async def get_by_id(self, provider_id: int) -> LoginProvider | None:
        now = time.monotonic()
        if provider_id in self._by_id_cache:
            cached, ts = self._by_id_cache[provider_id]
            if now - ts < _CACHE_TTL_SECONDS:
                return cached
            del self._by_id_cache[provider_id]
        lp = await LoginProvider.get_by_id(provider_id)
        if lp is not None:
            self._by_id_cache[provider_id] = (lp, now)
        return lp

    async def get_by_iss(self, issuer: str) -> LoginProvider | ConfigLoginProvider | None:
        try:
            result = await LoginProvider.get_login_provider_from_iss(issuer)
            if result:
                return result
        except Exception:
            _logger.debug(
                "DB lookup for login_providers failed (table may not exist), "
                "falling back to config-based providers."
            )
        return self._get_config_provider_by_iss(issuer)

    @staticmethod
    def _get_config_provider_by_iss(issuer: str) -> ConfigLoginProvider | None:
        for provider in _config.auth_default_login_providers:
            if provider.issuer == issuer:
                return provider
        return None

    async def get_all(self, user_type: str | None = None) -> list[LoginProvider]:
        if user_type:
            return await LoginProvider.get_by_user_type(user_type)
        return await LoginProvider.get_all()

    @staticmethod
    def read_extra_authorize_params(login_provider: LoginProvider) -> dict:
        if not login_provider.extra_authorize_params:
            return {}
        try:
            import json
            return json.loads(login_provider.extra_authorize_params)
        except Exception:
            return {}

