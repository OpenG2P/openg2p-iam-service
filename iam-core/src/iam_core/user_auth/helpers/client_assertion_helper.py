from datetime import datetime, timedelta
from jose import jwt as jose_jwt

from openg2p_fastapi_common.errors.http_exceptions import InternalServerError

from iam_core.models import LoginProvider
from iam_core.schemas import TokenEndpointAuthMethod

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def _jwt_payload(login_provider: LoginProvider) -> dict:
    aud = login_provider.jwt_assertion_aud or login_provider.token_endpoint
    if not aud:
        raise InternalServerError(
            "G2P-AUT-503",
            "token_endpoint (or jwt_assertion_aud) is required for client assertion.",
        )
    now = datetime.utcnow()
    return {
        "iss": login_provider.client_id,
        "sub": login_provider.client_id,
        "aud": aud,
        "iat": now,
        "exp": now + timedelta(hours=1),
    }


async def generate_keymanager_client_assertion(
    login_provider: LoginProvider,
    *,
    keymanager_helper,
    **kw,
) -> tuple[str, str]:
    if (
        login_provider.token_endpoint_auth_method
        != TokenEndpointAuthMethod.private_key_jwt_keymanager
    ):
        raise InternalServerError(
            "G2P-AUT-503",
            "LoginProvider is not configured for keymanager client assertions.",
        )
    if not keymanager_helper:
        raise InternalServerError(
            "G2P-AUT-503",
            "Keymanager helper is required for keymanager client assertions.",
        )

    token = await keymanager_helper.create_jwt_token(
        _jwt_payload(login_provider),
        km_app_id=login_provider.keymanager_app_id,
        km_ref_id=login_provider.keymanager_ref_id,
        **kw,
    )
    return (CLIENT_ASSERTION_TYPE, token)


def generate_private_key_client_assertion(
    login_provider: LoginProvider,
    **kw,
) -> tuple[str, str]:
    if login_provider.token_endpoint_auth_method != TokenEndpointAuthMethod.private_key_jwt:
        raise InternalServerError(
            "G2P-AUT-503",
            "LoginProvider is not configured for private_key_jwt client assertions.",
        )
    key_pem = getattr(login_provider, "client_private_key", None)
    if not key_pem:
        raise InternalServerError(
            "G2P-AUT-503",
            "client_private_key is required for private_key_jwt flow.",
        )
    if isinstance(key_pem, (bytes, bytearray)):
        key_pem = key_pem.decode("utf-8")

    alg = kw.get("private_key_jwt_alg") or "RS256"
    kid = kw.get("private_key_jwt_kid")
    headers = {"typ": "JWT"}
    if isinstance(kid, str) and kid:
        headers["kid"] = kid
    
    token = jose_jwt.encode(
        _jwt_payload(login_provider),
        key_pem,
        algorithm=alg,
        headers=headers,
    )
    return (CLIENT_ASSERTION_TYPE, token)