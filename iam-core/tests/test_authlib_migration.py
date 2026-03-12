import types

import pytest
from jose import jwt as jose_jwt
from openg2p_fastapi_common.errors.http_exceptions import ForbiddenError
from openg2p_iam_core.services.token_validator_service import TokenValidatorService
from openg2p_iam_core.user_auth.config import ApiAuthSettings
from openg2p_iam_core.user_auth.dependencies import claim_in, require_user_type


@pytest.mark.asyncio
async def test_require_user_type_accepts_legacy_user_type_field():
    checker = require_user_type("staff")
    result = await checker(auth={"userType": "staff"})
    assert result["userType"] == "staff"


@pytest.mark.asyncio
async def test_claim_in_accepts_string_and_list_values():
    checker_string = claim_in("roles", {"agent"})
    checker_list = claim_in("roles", {"agent"})

    assert (await checker_string(auth={"roles": "agent"}))["roles"] == "agent"
    assert "agent" in (await checker_list(auth={"roles": ["agent", "staff"]}))["roles"]


@pytest.mark.asyncio
async def test_token_validator_hybrid_mode_merges_claims():
    validator = TokenValidatorService()
    token = jose_jwt.encode(
        {"iss": "https://issuer", "aud": "portal", "sub": "u-1"},
        "secret",
        algorithm="HS256",
    )

    async def mock_provider(iss):
        return types.SimpleNamespace(
            id=1,
            client_id="client",
            client_secret="secret",
            token_endpoint_auth_method="client_secret_post",
        )

    async def mock_introspection(*args, **kwargs):
        return {"active": True, "user_type": "staff", "roles": ["staff"]}

    async def mock_decode(*args, **kwargs):
        return {"sub": "u-1", "iss": "https://issuer", "aud": "portal"}

    validator._get_login_provider_db_by_iss = mock_provider
    validator._oidc.introspect_token = mock_introspection
    validator._oidc.decode_jwt = mock_decode

    result = await validator.validate(
        jwt_token=token,
        jwt_id_token=None,
        api_auth_settings=ApiAuthSettings(
            enabled=True,
            validation_mode="hybrid",
            claim_name="roles",
            claim_values=["staff"],
        ),
        issuers_list=["https://issuer"],
        audiences_list=["portal"],
    )
    assert result.user_type == "staff"
    assert result.sub == "u-1"


@pytest.mark.asyncio
async def test_token_validator_claim_gate_rejects_mismatch():
    validator = TokenValidatorService()
    token = jose_jwt.encode(
        {"iss": "https://issuer", "aud": "portal", "sub": "u-1"},
        "secret",
        algorithm="HS256",
    )

    async def mock_provider(iss):
        return types.SimpleNamespace(
            id=1,
            client_id="client",
            client_secret="secret",
            token_endpoint_auth_method="client_secret_post",
        )

    async def mock_decode(*args, **kwargs):
        return {"sub": "u-1", "iss": "https://issuer", "aud": "portal", "roles": ["staff"]}

    validator._get_login_provider_db_by_iss = mock_provider
    validator._oidc.decode_jwt = mock_decode

    with pytest.raises(ForbiddenError):
        await validator.validate(
            jwt_token=token,
            jwt_id_token=None,
            api_auth_settings=ApiAuthSettings(
                enabled=True,
                validation_mode="jwt",
                claim_name="roles",
                claim_values=["agent"],
            ),
            issuers_list=["https://issuer"],
            audiences_list=["portal"],
        )
