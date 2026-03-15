"""Resolves legacy auth state format (JSON with 'p' = provider id, 'r' = redirect_uri)."""

import orjson


class LegacyStateResolver:
    """Handles legacy state format for auth callback when transaction store has no match."""

    @staticmethod
    def resolve(state_value: str | None) -> tuple[int | None, str]:
        """
        Parse legacy state. Returns (login_provider_id, redirect_uri) or (None, "/").
        """
        if not state_value:
            return None, "/"
        try:
            state = orjson.loads(state_value)
        except orjson.JSONDecodeError:
            return None, "/"
        login_provider_id = state.get("p")
        if login_provider_id is None:
            return None, "/"
        redirect_uri = state.get("r", "/")
        return login_provider_id, redirect_uri
