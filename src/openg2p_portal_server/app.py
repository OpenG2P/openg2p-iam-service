# ruff: noqa: E402

import asyncio

from .config import Settings

_config = Settings.get_config()

from openg2p_fastapi_auth_models.models import LoginProvider
from openg2p_fastapi_auth.app import Initializer as AuthInitializer

from .controllers.auth_controller import AuthController
from .controllers.oauth_controller import OAuthController
from .services.user_service import UserService
from .models import User, UserLoginLog, Department



class Initializer(AuthInitializer):
    def initialize(self, **kwargs):
        super().initialize()

        UserService()
        AuthController().post_init()
        OAuthController().post_init()

    def migrate_database(self, args):
        super().migrate_database(args)

        async def migrate():
            await LoginProvider.create_migrate()
            await User.create_migrate()
            await UserLoginLog.create_migrate()
            await Department.create_migrate()

        asyncio.run(migrate())
