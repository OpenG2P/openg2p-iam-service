from iam_core.models import LoginProvider


def pkce_kwargs(login_provider: LoginProvider, code_verifier: str | None) -> dict:
    """Build PKCE kwargs for token exchange when PKCE is enabled."""
    if login_provider.enable_pkce and code_verifier:
        return {"code_verifier": code_verifier}
    return {}
