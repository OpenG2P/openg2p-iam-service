import json
import logging
import time

import httpx
from openg2p_fastapi_common.service import BaseService
from pydantic import BaseModel

from iam_core.models import LoginProvider
from iam_core.user_auth.config import Settings

_CACHE_TTL_SECONDS = 60
_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class _ApiLoginProvider(BaseModel):
    """Lightweight stand-in for LoginProvider, built from the API response."""

    issuer: str
    jwks_uri: str | None = None
    server_metadata_url: str | None = None
    audiences: str | None = None
    adapter_name: str | None = None
    token_endpoint_auth_method: str | None = None
    client_id: str | None = None

    # Fields expected by OidcClient.get_server_metadata cache key
    id: int | None = None

    # Fields accessed by OidcClient but not needed for validation
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    userinfo_endpoint: str | None = None
    extra_authorize_params: str | None = None

    @property
    def audiences_list(self) -> list[str]:
        if not self.audiences:
            return []
        return json.loads(self.audiences)


class ProviderRepository(BaseService):
    def __init__(self):
        super().__init__()
        self._by_id_cache: dict[int, tuple[LoginProvider, float]] = {}
        self._by_iss_cache: dict[str, tuple[_ApiLoginProvider, float]] = {}

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

    async def get_by_iss(self, issuer: str):
        # Try DB first
        try:
            result = await LoginProvider.get_login_provider_from_iss(issuer)
            if result:
                return result
        except Exception:
            pass

        # Fallback: check in-memory cache from API
        now = time.monotonic()
        if issuer in self._by_iss_cache:
            cached, ts = self._by_iss_cache[issuer]
            if now - ts < _CACHE_TTL_SECONDS:
                return cached
            del self._by_iss_cache[issuer]

        # Fallback: fetch from IAM Portal API
        return await self._fetch_provider_from_api(issuer)

    async def _fetch_provider_from_api(self, issuer: str) -> _ApiLoginProvider | None:
        api_url = getattr(_config, "auth_provider_api_url", None)
        if not api_url:
            _logger.warning(
                "No auth_provider_api_url configured and login_providers "
                "table is not available. Cannot resolve issuer: %s",
                issuer,
            )
            return None

        url = f"{api_url.rstrip('/')}/identity-providers/get_provider_by_issuer"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(url, params={"issuer": issuer})
                response.raise_for_status()
                data = response.json()
                provider = _ApiLoginProvider.model_validate(data)
                self._by_iss_cache[issuer] = (provider, time.monotonic())
                return provider
        except Exception:
            _logger.exception(
                "Failed to fetch login provider from API for issuer: %s", issuer
            )
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
            return json.loads(login_provider.extra_authorize_params)
        except Exception:
            return {}
