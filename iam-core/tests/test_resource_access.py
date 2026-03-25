import pytest
from openg2p_fastapi_common.errors.http_exceptions import ForbiddenError

from iam_core.user_auth.dependencies import check_resource_access, enforce_resource_access


def test_enforce_resource_access_with_client_id_passes():
    auth = {
        "client_roles": {
            "account": ["view-profile", "edit-profile"],
            "other": ["manage-users"],
        }
    }

    result = enforce_resource_access(
        auth=auth,
        allowed_roles={"view-profile"},
        client_id="account",
    )

    assert result is auth


def test_enforce_resource_access_with_client_id_forbidden():
    auth = {"client_roles": {"account": ["edit-profile"]}}

    with pytest.raises(ForbiddenError):
        enforce_resource_access(
            auth=auth,
            allowed_roles={"view-profile"},
            client_id="account",
        )


@pytest.mark.asyncio
async def test_check_resource_access_without_client_id_checks_all_clients():
    checker = check_resource_access(allowed_roles={"manage-users"}, client_id=None)

    auth = {
        "client_roles": {
            "account": ["view-profile"],
            "admin-client": ["manage-users"],
        }
    }

    result = await checker(auth=auth)
    assert result is auth


@pytest.mark.asyncio
async def test_check_resource_access_without_client_id_forbidden_when_no_match():
    checker = check_resource_access(allowed_roles={"manage-users"}, client_id=None)

    auth = {
        "client_roles": {
            "account": ["view-profile"],
            "admin-client": ["view-audit"],
        }
    }

    with pytest.raises(ForbiddenError):
        await checker(auth=auth)
