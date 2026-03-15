import enum

from pydantic import BaseModel, field_validator


class TokenEndpointAuthMethod(enum.Enum):
    private_key_jwt_keymanager = "private_key_jwt_keymanager"
    client_secret_basic = "client_secret_basic"
    client_secret_post = "client_secret_post"


class OauthProviderParameters(BaseModel): #TODO: Remove
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str | None = None
    jwks_uri: str | None = None

    client_id: str
    client_secret: str | None = None
    token_endpoint_auth_method: TokenEndpointAuthMethod = (
        TokenEndpointAuthMethod.client_secret_post
    )
    client_assertion_jwk: dict | str | bytes | None = None
    client_assertion_jwt_aud: str | None = None
    client_assertion_jwk_keymanager: str | None = None

    response_type: str = "code"
    oauth_callback_url: str
    scope: str = "openid profile email"
    enable_pkce: bool = True
    code_challenge: str = ""
    code_challenge_method: str = "S256"
    extra_authorize_params: dict = {}

    @field_validator("enable_pkce", mode="before")
    @classmethod
    def validate_pkce(cl, val):
        if isinstance(val, bool) and val:
            return True
        elif isinstance(val, str) and val.lower() != "false":
            return True
        return False
