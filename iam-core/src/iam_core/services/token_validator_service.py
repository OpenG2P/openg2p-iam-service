from typing import Any

from authlib.jose.errors import JoseError
from jose import jwt as jose_jwt
from openg2p_fastapi_common.errors.http_exceptions import ForbiddenError, UnauthorizedError
from openg2p_fastapi_common.service import BaseService

from iam_core.schemas import AuthCredentials
from iam_core.services.provider_repository import ProviderRepository
from iam_core.user_auth.adapters import AdapterFactory
from iam_core.user_auth.config import ApiAuthSettings


class TokenValidatorService(BaseService):
    def __init__(self):
        super().__init__()
        self._providers = ProviderRepository.get_component()
        self._adapters = AdapterFactory.get_component()

    async def _get_login_provider_db_by_iss(self, iss: str):
        return await self._providers.get_by_iss(iss)

    @staticmethod
    def _validate_iss_aud(
        unverified_payload: dict,
        issuers_list: list[str],
        audiences_list: list[str],
    ) -> None:
        iss = unverified_payload.get("iss")
        aud = unverified_payload.get("aud")
        if (not iss) or (iss not in issuers_list):
            raise UnauthorizedError(message=f"Unauthorized. Unknown Issuer. {iss}")

        if not audiences_list:
            return
        if (
            (not aud)
            or (isinstance(aud, list) and not set(audiences_list).issubset(set(aud)))
            or (isinstance(aud, str) and aud not in audiences_list)
        ):
            raise UnauthorizedError(message="Unauthorized. Unknown Audience.")

    @staticmethod
    def _validate_route_claims(
        claims: dict,
        api_auth_settings: ApiAuthSettings,
    ) -> None:
        claim_to_check = api_auth_settings.claim_name
        claim_values = api_auth_settings.claim_values or []
        if not claim_to_check:
            return
        source_claim = claims.get(claim_to_check)
        if source_claim is None:
            raise ForbiddenError(message="Forbidden. Claim(s) missing.")
        if isinstance(source_claim, str):
            if len(claim_values) != 1 or claim_values[0] != source_claim:
                raise ForbiddenError(message="Forbidden. Claim doesn't match.")
            return
        if not all(v in source_claim for v in claim_values):
            raise ForbiddenError(message="Forbidden. Claim(s) don't match.")

    @staticmethod
    def _combine_claims(*claim_dicts: dict[str, Any] | None) -> dict[str, Any]:
        result = {}
        for claim_dict in claim_dicts:
            if not claim_dict:
                continue
            for key, value in claim_dict.items():
                if value is not None:
                    result[key] = value
        return result

    async def validate(
        self,
        jwt_token: str,
        jwt_id_token: str | None,
        api_auth_settings: ApiAuthSettings,
        issuers_list: list[str],
        audiences_list: list[str],
    ) -> AuthCredentials:
        try:
            unverified_payload = jose_jwt.get_unverified_claims(jwt_token)
        except Exception as e:
            raise UnauthorizedError(
                message=f"Unauthorized. Jwt expired. {repr(e)}"
            ) from e

        self._validate_iss_aud(unverified_payload, issuers_list, audiences_list)
        iss = unverified_payload.get("iss")
        login_provider = await self._get_login_provider_db_by_iss(iss)
        if not login_provider:
            raise UnauthorizedError(message=f"Unauthorized. Unknown Issuer. {iss}")
        adapter = self._adapters.resolve_for_provider(login_provider)

        validation_mode = api_auth_settings.validation_mode or "jwt"
        introspected_claims = None
        if validation_mode in ("introspection", "hybrid"):
            introspected_claims = await adapter.introspect_token(
                login_provider,
                jwt_token,
                endpoint=api_auth_settings.introspection_endpoint,
            )

        if validation_mode in ("jwt", "hybrid"):
            try:
                verified_claims = await adapter.decode_access_token(
                    login_provider,
                    jwt_token,
                    iss=iss,
                )
            except JoseError as e:
                raise UnauthorizedError(
                    message=f"Unauthorized. Invalid Jwt. {repr(e)}"
                ) from e
        else:
            verified_claims = {}

        id_token_claims = None
        if jwt_id_token:
            try:
                id_token_claims = await adapter.decode_id_token(
                    login_provider,
                    jwt_id_token,
                    jwt_token=jwt_token,
                    iss=iss,
                )
            except JoseError as e:
                raise UnauthorizedError(
                    message=f"Unauthorized. Invalid Jwt ID Token. {repr(e)}"
                ) from e

        claims = self._combine_claims(
            unverified_payload,
            introspected_claims,
            verified_claims,
            id_token_claims,
        )
        claims = adapter.normalize_claims(claims, login_provider=login_provider)
        try:
            adapter.validate_claims(claims, login_provider=login_provider)
        except ValueError as e:
            raise UnauthorizedError(message=f"Unauthorized. {str(e)}") from e
        self._validate_route_claims(claims, api_auth_settings)
        claims["credentials"] = jwt_token
        return AuthCredentials.model_validate(claims)
