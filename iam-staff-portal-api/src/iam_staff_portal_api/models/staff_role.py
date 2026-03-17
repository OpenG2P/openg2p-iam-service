from typing import Optional

from openg2p_fastapi_common.models import BaseORMModelWithTimes
from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column


class StaffRole(BaseORMModelWithTimes):
    __tablename__ = "staff_roles"

    role_mnemonic: Mapped[str] = mapped_column(String, nullable=False)
    role_description: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    application_id: Mapped[int] = mapped_column(Integer, nullable=False)
