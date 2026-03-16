import json
import time

from openg2p_fastapi_common.service import BaseService

from iam_core.models import LoginProvider, UserTypeEnum
from iam_core.schemas import TokenEndpointAuthMethod
from iam_core.user_auth.config import Settings

_config = Settings.get_config(strict=False)
_CACHE_TTL_SECONDS = 60


class ProviderRepository(BaseService):
    def __init__(self):
        super().__init__()
        self._by_id_cache: dict[int, tuple[LoginProvider, float]] = {}

    @staticmethod
    def _provider_from_config(provider_dict: dict) -> LoginProvider:
        provider_fields = set(LoginProvider.__mapper__.columns.keys())
        filtered = {k: v for k, v in provider_dict.items() if k in provider_fields}
        if isinstance(filtered.get("user_type"), str):
            filtered["user_type"] = UserTypeEnum(filtered["user_type"].lower())
        if isinstance(filtered.get("token_endpoint_auth_method"), str):
            filtered["token_endpoint_auth_method"] = TokenEndpointAuthMethod(
                filtered["token_endpoint_auth_method"]
            )
        filtered["adapter_name"] = (filtered.get("adapter_name") or "default_oidc").lower()
        return LoginProvider(**filtered)

    async def get_by_id(self, provider_id: int) -> LoginProvider | None:
        now = time.monotonic()
        if provider_id in self._by_id_cache:
            cached, ts = self._by_id_cache[provider_id]
            if now - ts < _CACHE_TTL_SECONDS:
                return cached
            del self._by_id_cache[provider_id]
        if _config.login_providers_list:
            for provider in _config.login_providers_list:
                if provider.get("id") == provider_id:
                    lp = self._provider_from_config(provider)
                    self._by_id_cache[provider_id] = (lp, now)
                    return lp
            return None
        lp = await LoginProvider.get_by_id(provider_id)
        if lp is not None:
            self._by_id_cache[provider_id] = (lp, now)
        return lp

    async def get_by_iss(self, issuer: str) -> LoginProvider | None:
        if _config.login_providers_list:
            for provider in _config.login_providers_list:
                if issuer == provider.get("iss"):
                    return self._provider_from_config(provider)
            return None
        if await LoginProvider.table_exists_cached():
            return await LoginProvider.get_login_provider_from_iss(issuer)
        return None

    async def get_all(self, user_type: str | None = None) -> list[LoginProvider]:
        if _config.login_providers_list:
            providers = [self._provider_from_config(p) for p in _config.login_providers_list]
            if not user_type:
                return providers
            normalized = user_type.lower()
            return [p for p in providers if p.user_type.value == normalized]

        if user_type:
            return await LoginProvider.get_by_user_type(user_type)
        return await LoginProvider.get_all()

    @staticmethod
    def read_extra_authorize_params(login_provider: LoginProvider) -> dict:
        if not login_provider.extra_authorize_params:
            return {}
        try:
            return json.loads(login_provider.extra_authorize_params)
        except Exception:
            return {}
