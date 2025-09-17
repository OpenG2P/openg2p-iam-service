# ruff: noqa: E402

import asyncio

from .config import Settings

_config = Settings.get_config()

from openg2p_fastapi_common.app import Initializer

from .controllers.auth_controller import AuthController
from .controllers.oauth_controller import OAuthController
from .services.user_service import UserService
from .models.orm.user_orm import UserORM


class Initializer(Initializer):
    def initialize(self, **kwargs):
        super().initialize()
        # Initialize all Services, Controllers, any utils here.
        UserService()
        AuthController().post_init()
        OAuthController().post_init()

    def migrate_database(self, args):
        super().migrate_database(args)

        async def migrate():
            await UserORM.create_migrate()

        asyncio.run(migrate())