from iam_core.services import AuthService
from openg2p_fastapi_common.controller import BaseController


class IdentityProviderController(BaseController):
    user_type = "staff"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.router.prefix += "/identity-providers"
        self.router.tags += ["/identity-providers"]
        self.auth_service = AuthService(user_type=self.user_type)

        self.router.add_api_route(
            "/get_provider_by_issuer",
            self.get_provider_by_issuer,
            methods=["GET"],
        )

    async def get_provider_by_issuer(self, issuer: str):
        return await self.auth_service.get_provider_by_issuer(issuer)
