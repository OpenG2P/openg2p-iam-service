import json
import types

import pytest
from jose import jwt as jose_jwt
from openg2p_fastapi_common.errors.http_exceptions import ForbiddenError
from iam_core.services.token_validator_service import TokenValidatorService
from iam_core.user_auth.config import ApiAuthSettings
from iam_core.user_auth.dependencies import claim_in, require_auth


@pytest.mark.asyncio
async def test_require_auth_returns_auth_object():
    checker = require_auth()
    auth = {"sub": "user-1", "roles": ["staff"]}

    result = await checker(auth=auth)

    assert result is auth


@pytest.mark.asyncio
async def test_claim_in_accepts_string_and_list_values():
    checker_string = claim_in("roles", {"agent"})
    checker_list = claim_in("roles", {"agent"})

    assert (await checker_string(auth={"roles": "agent"}))["roles"] == "agent"
    assert "agent" in (await checker_list(auth={"roles": ["agent", "staff"]}))["roles"]


@pytest.mark.asyncio
async def test_token_validator_hybrid_mode_merges_claims():
    validator = TokenValidatorService.get_component()
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
            issuer="https://issuer",
            audiences=json.dumps(["portal"]),
            audiences_list=["portal"],
        )

    async def mock_introspection(*args, **kwargs):
        return {"active": True, "roles": ["staff"]}

    async def mock_decode(*args, **kwargs):
        return {"sub": "u-1", "iss": "https://issuer", "aud": "portal"}

    mock_adapter = types.SimpleNamespace(
        introspect_token=mock_introspection,
        decode_access_token=mock_decode,
        decode_id_token=mock_decode,
        normalize_claims=lambda claims, **kw: claims,
        validate_claims=lambda *a, **k: None,
    )

    validator._get_login_provider_db_by_iss = mock_provider
    validator._adapters.resolve_for_provider = lambda lp: mock_adapter

    result = await validator.validate(
        jwt_token=token,
        jwt_id_token=None,
        api_auth_settings=ApiAuthSettings(
            enabled=True,
            validation_mode="hybrid",
            claim_name="roles",
            claim_values=["staff"],
        ),
    )
    assert result.sub == "u-1"
    assert "user_type" not in result.model_dump()


@pytest.mark.asyncio
async def test_token_validator_claim_gate_rejects_mismatch():
    validator = TokenValidatorService.get_component()
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
            issuer="https://issuer",
            audiences=json.dumps(["portal"]),
            audiences_list=["portal"],
        )

    async def mock_decode(*args, **kwargs):
        return {"sub": "u-1", "iss": "https://issuer", "aud": "portal", "roles": ["staff"]}

    mock_adapter = types.SimpleNamespace(
        introspect_token=None,
        decode_access_token=mock_decode,
        decode_id_token=mock_decode,
        normalize_claims=lambda claims, **kw: claims,
        validate_claims=lambda *a, **k: None,
    )

    validator._get_login_provider_db_by_iss = mock_provider
    validator._adapters.resolve_for_provider = lambda lp: mock_adapter

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
        )
