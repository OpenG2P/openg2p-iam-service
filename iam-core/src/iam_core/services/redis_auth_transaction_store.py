import json
import secrets
from datetime import datetime, timedelta, timezone

from openg2p_fastapi_common.service import BaseService

from iam_core.schemas import AuthTransaction
from iam_core.user_auth.config import Settings

_config = Settings.get_config(strict=False)
REDIS_KEY_PREFIX = "auth_tx:"


class RedisAuthTransactionStore(BaseService):
    """Redis-backed auth transaction store with TTL. Same API as AuthTransactionStore."""

    def __init__(self, ttl_seconds: int = 300, redis_url: str | None = None):
        super().__init__()
        self._ttl = ttl_seconds
        self._redis_url = redis_url or getattr(
            _config, "auth_redis_url", "redis://localhost:6379/0"
        )
        self._client = None

    def _get_client(self):
        if self._client is None:
            import redis

            self._client = redis.from_url(
                self._redis_url,
                decode_responses=True,
            )
        return self._client

    def create(
        self,
        login_provider_id: int,
        redirect_uri: str,
        server_metadata: dict | None = None,
    ) -> AuthTransaction:
        now = datetime.now(tz=timezone.utc)
        auth_transaction = AuthTransaction(
            state=secrets.token_urlsafe(32),
            code_verifier=secrets.token_urlsafe(32),
            nonce=secrets.token_urlsafe(),
            login_provider_id=login_provider_id,
            redirect_uri=redirect_uri,
            created_at=now,
            expires_at=now + timedelta(seconds=self._ttl),
            server_metadata=server_metadata,
        )
        key = f"{REDIS_KEY_PREFIX}{auth_transaction.state}"
        payload = auth_transaction.model_dump(mode="json")
        self._get_client().setex(
            key,
            self._ttl,
            json.dumps(payload),
        )
        return auth_transaction

    def get_and_pop(self, state: str | None) -> AuthTransaction | None:
        if not state:
            return None
        key = f"{REDIS_KEY_PREFIX}{state}"
        client = self._get_client()
        raw = client.get(key)
        if raw is None:
            return None
        client.delete(key)
        try:
            data = json.loads(raw)
            auth_transaction = AuthTransaction.model_validate(data)
            if datetime.now(tz=timezone.utc) > auth_transaction.expires_at:
                return None
            return auth_transaction
        except Exception:
            return None
