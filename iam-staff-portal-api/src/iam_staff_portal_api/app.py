# ruff: noqa: E402

import asyncio

from .config import Settings

_config = Settings.get_config()

print("DB datasource:", _config.db_datasource)

from iam_core.models import LoginProvider
from iam_core.user_auth.app import Initializer as AuthInitializer

from .controllers import (
    AuthController,
    IdentityProviderController,
    OAuthCallbackController,
    UserAccessController
)
from .models import (
    StaffApplicationAction,
    StaffPortalApplication,
    StaffRole,
    StaffRoleAction,
)


class Initializer(AuthInitializer):
    def initialize(self, **kwargs):
        super().initialize()

        AuthController().post_init()
        OAuthCallbackController().post_init()
        UserAccessController().post_init()
        IdentityProviderController().post_init()

    def migrate_database(self, args):
        super().migrate_database(args)

        async def migrate():
            await LoginProvider.create_migrate()
            await StaffPortalApplication.create_migrate()
            await StaffRole.create_migrate()
            await StaffApplicationAction.create_migrate()
            await StaffRoleAction.create_migrate()

        asyncio.run(migrate())
