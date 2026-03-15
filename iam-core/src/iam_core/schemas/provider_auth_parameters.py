import enum


class TokenEndpointAuthMethod(enum.Enum):
    private_key_jwt_keymanager = "private_key_jwt_keymanager"
    client_secret_basic = "client_secret_basic"
    client_secret_post = "client_secret_post"
