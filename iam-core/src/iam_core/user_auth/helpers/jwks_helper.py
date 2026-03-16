import logging

import httpx
from openg2p_fastapi_common.errors.http_exceptions import InternalServerError

from iam_core.context import jwks_cache
from iam_core.user_auth.config import Settings

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


async def get_jwks(metadata: dict, issuer: str | None = None) -> dict:
    """Fetch and cache JWKS for the given OIDC metadata. Uses issuer for cache key."""
    cache = jwks_cache.get() or {}
    if issuer and issuer in cache:
        return cache[issuer]

    jwks_url = metadata.get("jwks_uri")
    if not jwks_url and issuer:
        jwks_url = f"{issuer.rstrip('/')}/.well-known/jwks.json"
    if not jwks_url:
        raise InternalServerError(
            code="G2P-AUT-500",
            message="Missing jwks_uri for provider.",
        )

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(jwks_url)
        response.raise_for_status()
        jwks = response.json()

    if issuer:
        cache[issuer] = jwks
        jwks_cache.set(cache)
    return jwks
