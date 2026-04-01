from fastapi_cache import FastAPICache
from fastapi_cache.backends.inmemory import InMemoryBackend


def init_cache():
    FastAPICache.init(InMemoryBackend(), prefix="iam-staff-cache")


def role_cache_key(func, namespace: str, *args, **kwargs):
    """
    Build a cache key scoped only by role mnemonic.
    """
    call_args = kwargs.get("args") or args
    call_kwargs = kwargs.get("kwargs") or {}

    role_mnemonic = call_kwargs.get("role_mnemonic")
    if role_mnemonic is None and len(call_args) > 1:
        role_mnemonic = call_args[1]

    return f"{namespace}:{role_mnemonic}"