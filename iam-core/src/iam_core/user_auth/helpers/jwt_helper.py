import logging

from authlib.jose import JsonWebKey, jwt
from openg2p_fastapi_common.errors.http_exceptions import UnauthorizedError

from openg2p_iam_core.user_auth.config import Settings

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


def decode_jwt(
    token: str,
    jwks: dict,
    verify_exp: bool = True,
    nonce: str | None = None,
    access_token: str | None = None,
) -> dict:
    """Decode and validate a JWT using the given JWKS. Returns claims dict."""
    key_set = JsonWebKey.import_key_set(jwks)
    claims = jwt.decode(token, key_set, claims_params={"nonce": nonce})
    if verify_exp:
        claims.validate()
    claim_dict = dict(claims)
    if nonce and claim_dict.get("nonce") != nonce:
        raise UnauthorizedError("G2P-AUT-401", "Nonce mismatch")
    if access_token and claim_dict.get("at_hash") is None:
        _logger.debug("ID token missing at_hash while access_token is present.")
    return claim_dict
