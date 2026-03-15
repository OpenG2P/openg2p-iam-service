import secrets
from datetime import datetime, timedelta, timezone

from openg2p_iam_core.schemas import AuthTransaction


class AuthTransactionStore:
    """Simple in-memory transaction store with TTL.""" # TODO: This needs to be replaced with Redis 

    def __init__(self, ttl_seconds: int = 300):
        self._store: dict[str, AuthTransaction] = {}
        self._ttl = ttl_seconds

    def create(self, login_provider_id: int, redirect_uri: str) -> AuthTransaction:
        now = datetime.now(tz=timezone.utc)
        auth_transaction: AuthTransaction = AuthTransaction(
            state=secrets.token_urlsafe(32),
            code_verifier=secrets.token_urlsafe(32),
            nonce=secrets.token_urlsafe(),
            login_provider_id=login_provider_id,
            redirect_uri=redirect_uri,
            created_at=now,
            expires_at=now + timedelta(seconds=self._ttl),
        )
        self._store[auth_transaction.state] = auth_transaction
        return auth_transaction

    def get_and_pop(self, state: str | None) -> AuthTransaction | None:
        if not state:
            return None
        auth_transaction: AuthTransaction = self._store.pop(state, None)
        if not auth_transaction:
            return None
        if datetime.now(tz=timezone.utc) > auth_transaction.expires_at:
            return None
        return auth_transaction


auth_transaction_store = AuthTransactionStore()
