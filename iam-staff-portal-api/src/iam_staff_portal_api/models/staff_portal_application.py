from typing import Optional

from openg2p_fastapi_common.models import BaseORMModelWithTimes
from sqlalchemy import String, Integer
from sqlalchemy.orm import Mapped, mapped_column


class StaffPortalApplication(BaseORMModelWithTimes):
    __tablename__ = "staff_portal_applications"

    application_mnemonic: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    application_description: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    icon_base64: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    width: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    application_url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    order: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
