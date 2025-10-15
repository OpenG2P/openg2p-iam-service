from typing import Optional
from openg2p_fastapi_auth_models.schemas import UserProfile as BaseUserProfile


class UserProfile(BaseUserProfile):
    auth_provider_id: Optional[int] = None
    user_id: Optional[str] = None
