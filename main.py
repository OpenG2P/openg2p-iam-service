#!/usr/bin/env python3

# ruff: noqa: I001

from openg2p_portal_server.app import (
    Initializer as BeneficiaryPortalInitializer,
)
from openg2p_fastapi_common.ping import PingInitializer

main_init = BeneficiaryPortalInitializer()
PingInitializer()

main_init.main()
