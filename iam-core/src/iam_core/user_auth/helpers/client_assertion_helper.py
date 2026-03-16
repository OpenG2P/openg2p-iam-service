from datetime import datetime, timedelta, timezone

from openg2p_fastapi_common.errors.http_exceptions import InternalServerError

from openg2p_iam_core.models import LoginProvider
from openg2p_iam_core.schemas import TokenEndpointAuthMethod


async def generate_client_assertion(
    login_provider: LoginProvider,
    keymanager_helper=None,
    **kw,
) -> tuple[str, str]:
    """
    Returns (keymanager_assertion_type, keymanager_token) for use in token endpoint.
    """
    assertion_type = login_provider.token_endpoint_auth_method

    if assertion_type != TokenEndpointAuthMethod.private_key_jwt_keymanager:
        raise InternalServerError(
            "G2P-AUT-503",
            "Unsupported client assertion configuration.",
        )

    if not keymanager_helper:
        raise InternalServerError(
            "G2P-AUT-503",
            "Keymanager helper is required for keymanager flow.",
        )

    aud = login_provider.jwt_assertion_aud or login_provider.token_endpoint
    iat = datetime.now(tz=timezone.utc).replace(tzinfo=None)
    exp = iat + timedelta(hours=1)
    keymanager_token = await keymanager_helper.create_jwt_token(
        {
            "iss": login_provider.client_id,
            "sub": login_provider.client_id,
            "aud": aud,
            "iat": int(iat.timestamp()),
            "exp": int(exp.timestamp()),
        },
        km_app_id=login_provider.keymanager_app_id,
        km_ref_id=login_provider.keymanager_ref_id,
        **kw,
    )
    return (
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        keymanager_token,
    )
