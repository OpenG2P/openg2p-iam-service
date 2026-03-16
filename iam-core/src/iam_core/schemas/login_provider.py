from pydantic import BaseModel


class LoginProviderResponse(BaseModel):
    id: int
    name: str
    protocol: str = "oidc"
    displayName: str | dict
    displayIconUrl: str


class LoginProviderHttpResponse(BaseModel):
    loginProviders: list[LoginProviderResponse]


class StartAuthTransactionResponse(BaseModel):
    redirectUrl: str
    state: str
