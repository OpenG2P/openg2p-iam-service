import types

import pytest

from iam_core.schemas import AuthCredentials
from iam_core.user_auth.adapters.implementations.esignet_adapter import EsignetAdapter
from iam_core.user_auth.adapters.implementations.keycloak_adapter import KeycloakAdapter
from iam_core.user_auth.dependencies import auth_principal


@pytest.mark.asyncio
async def test_auth_principal_extracts_client_roles_without_user_type():
    credentials = AuthCredentials.model_validate(
        {
            "credentials": "token",
            "iss": "https://issuer",
            "sub": "user-1",
            "name": "Test User",
            "resource_access": {"staff-portal": {"roles": ["admin", "viewer"]}},
        }
    )

    principal = await auth_principal(credentials)

    assert principal.sub == "user-1"
    assert principal.name == "Test User"
    assert principal.client_roles == {"staff-portal": ["admin", "viewer"]}
    assert "user_type" not in principal.model_dump()


def test_keycloak_adapter_normalizes_roles_without_user_type():
    adapter = KeycloakAdapter()

    claims = adapter.normalize_claims(
        {
            "sub": "user-1",
            "realm_access": {"roles": ["staff"]},
            "resource_access": {"staff-portal": {"roles": ["viewer"]}},
        },
        login_provider=types.SimpleNamespace(),
    )

    assert claims["roles"] == ["staff", "viewer"]
    assert "user_type" not in claims


def test_esignet_adapter_keeps_roles_without_user_type():
    adapter = EsignetAdapter()

    claims = adapter.normalize_claims(
        {
            "sub": "user-1",
            "realm_access": {"roles": ["beneficiary"]},
        },
        login_provider=types.SimpleNamespace(),
    )

    assert claims["roles"] == ["beneficiary"]
    assert "user_type" not in claims
