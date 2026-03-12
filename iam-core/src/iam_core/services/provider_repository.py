import json

from openg2p_iam_core.models import LoginProvider, UserTypeEnum
from openg2p_iam_core.schemas import TokenEndpointAuthMethod
from openg2p_iam_core.user_auth.config import Settings

_config = Settings.get_config(strict=False)


class ProviderRepository:
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
        return LoginProvider(**filtered)

    async def get_by_id(self, provider_id: int) -> LoginProvider | None:
        if _config.login_providers_list:
            for provider in _config.login_providers_list:
                if provider.get("id") == provider_id:
                    return self._provider_from_config(provider)
            return None
        if await LoginProvider.table_exists_cached():
            return await LoginProvider.get_by_id(provider_id)
        return None

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

        if not await LoginProvider.table_exists_cached():
            return []

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
