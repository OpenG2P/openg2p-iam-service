import base64
from datetime import datetime, timedelta, timezone

from authlib.jose import JsonWebKey, jwt
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
    aud = login_provider.jwt_assertion_aud or login_provider.token_endpoint

    if assertion_type == TokenEndpointAuthMethod.private_key_jwt:
        if not login_provider.client_private_key:
            raise InternalServerError(
                "G2P-AUT-503",
                "client_private_key is required for private_key_jwt.",
            )
        encoded_private_key = base64.b64decode(login_provider.client_private_key)
        private_key = JsonWebKey.import_key(encoded_private_key)
        payload = {
            "iss": login_provider.client_id,
            "sub": login_provider.client_id,
            "aud": aud,
            "exp": datetime.utcnow() + timedelta(hours=1),
            "iat": datetime.utcnow(),
        }
        keymanager_token = jwt.encode(
            {"alg": "RS256"}, payload, private_key
        ).decode("utf-8")
        return assertion_type.value, keymanager_token

    if assertion_type == TokenEndpointAuthMethod.private_key_jwt_keymanager:
        if not keymanager_helper:
            raise InternalServerError(
                "G2P-AUT-503",
                "Keymanager helper is required for keymanager flow.",
            )
        km_app_id = getattr(login_provider, "keymanager_app_id", None)
        km_ref_id = getattr(login_provider, "keymanager_ref_id", None)
        if km_app_id is None or km_ref_id is None:
            app_id_ref_id = (login_provider.client_private_key or b"").decode("utf-8")
            if ":" in app_id_ref_id:
                km_app_id, km_ref_id = [x.strip() for x in app_id_ref_id.split(":", 1)]
            else:
                km_app_id, km_ref_id = app_id_ref_id or "", ""
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
            km_app_id=km_app_id,
            km_ref_id=km_ref_id,
            **kw,
        )
        return (
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            keymanager_token,
        )

    raise InternalServerError(
        "G2P-AUT-503",
        "Unsupported client assertion configuration.",
    )
