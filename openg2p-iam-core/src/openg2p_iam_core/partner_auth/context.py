from contextvars import ContextVar

jwks_cache: ContextVar[dict] = ContextVar("partner_jwks_cache", default=None)
