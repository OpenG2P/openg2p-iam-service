import time

from openg2p_fastapi_common.service import BaseService

from iam_core.models import LoginProvider

_CACHE_TTL_SECONDS = 60


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

    async def get_by_iss(self, issuer: str) -> LoginProvider | None:
        return await LoginProvider.get_login_provider_from_iss(issuer)

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
