import pytest
from fastapi import Request
from openg2p_fastapi_common.errors.http_exceptions import ForbiddenError
from iam_core.schemas import AuthCredentials
from iam_core.user_auth.auth.implementations import (
    AgentKeycloakAuth,
    BeneficiaryEsignetAuth,
    StaffKeycloakAuth,
)


def _request() -> Request:
    return Request({"type": "http", "method": "GET", "headers": []})


@pytest.mark.asyncio
async def test_staff_adapter_infers_user_type_from_roles():
    adapter = StaffKeycloakAuth()
    credentials = AuthCredentials.model_validate(
        {
            "credentials": "token",
            "iss": "https://issuer",
            "sub": "user-1",
            "realm_access": {"roles": ["staff"]},
            "resource_access": {"staff-portal": {"roles": ["staff"]}},
        }
    )

    principal = await adapter.adapt(_request(), credentials)

    assert principal.user_type == "staff"
    assert "staff" in principal.roles


@pytest.mark.asyncio
async def test_agent_adapter_infers_user_type_from_roles():
    adapter = AgentKeycloakAuth()
    credentials = AuthCredentials.model_validate(
        {
            "credentials": "token",
            "iss": "https://issuer",
            "sub": "user-1",
            "realm_access": {"roles": ["agent"]},
            "resource_access": {"agent-portal": {"roles": ["agent"]}},
        }
    )

    principal = await adapter.adapt(_request(), credentials)

    assert principal.user_type == "agent"
    assert "agent" in principal.roles


@pytest.mark.asyncio
async def test_beneficiary_esignet_infers_user_type_from_provider_roles():
    adapter = BeneficiaryEsignetAuth()
    credentials = AuthCredentials.model_validate(
        {
            "credentials": "token",
            "iss": "https://issuer",
            "sub": "user-1",
            "resource_access": {"google-client": {"roles": ["beneficiary"]}},
        }
    )

    principal = await adapter.adapt(_request(), credentials)

    assert principal.user_type == "beneficiary"
    assert principal.sub == "user-1"


@pytest.mark.asyncio
async def test_staff_adapter_rejects_non_staff_user():
    adapter = StaffKeycloakAuth()
    credentials = AuthCredentials.model_validate(
        {
            "credentials": "token",
            "iss": "https://issuer",
            "sub": "user-1",
            "user_type": "agent",
            "realm_access": {"roles": ["agent"]},
        }
    )

    with pytest.raises(ForbiddenError):
        await adapter.adapt(_request(), credentials)
