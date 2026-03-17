from openg2p_fastapi_common.models import BaseORMModelWithTimes
from sqlalchemy import Integer
from sqlalchemy.orm import Mapped, mapped_column


class StaffRoleAction(BaseORMModelWithTimes):
    __tablename__ = "staff_role_actions"

    role_id: Mapped[int] = mapped_column(Integer, nullable=False)
    action_id: Mapped[int] = mapped_column(Integer, nullable=False)
