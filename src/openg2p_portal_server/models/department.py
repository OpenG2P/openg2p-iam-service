from typing import Optional
import uuid

from openg2p_fastapi_common.context import dbengine
from openg2p_fastapi_common.models import BaseORMModelWithId
from sqlalchemy import String, Boolean, select
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column


class Department(BaseORMModelWithId):
    __tablename__ = "departments"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=uuid.uuid4)
    department_name: Mapped[str] = mapped_column(String, nullable=False)
    department_mnemonic: Mapped[str] = mapped_column(
        String, unique=True, nullable=False
    )
    base_url: Mapped[str] = mapped_column(String, nullable=False)
    bridge_relative_url: Mapped[str] = mapped_column(String, nullable=False)
    spar_relative_url: Mapped[str] = mapped_column(String, nullable=False)
    pbms_relative_url: Mapped[str] = mapped_column(String, nullable=False)
    registry_relative_url: Mapped[str] = mapped_column(String, nullable=False)
    superset_relative_url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    @classmethod
    async def get_all_active(cls) -> list["Department"]:
        """
        Get all active departments.
        """
        async_session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with async_session_maker() as session:

            result = await session.execute(select(cls).where(cls.active.is_(True)))
            return result.scalars().all()

    @classmethod
    async def get_by_code(cls, code: str) -> Optional["Department"]:
        """
        Get department by mnemonic code.
        """
        async_session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with async_session_maker() as session:

            result = await session.execute(
                select(cls).where(cls.department_mnemonic == code, cls.active.is_(True))
            )
            return result.scalar_one_or_none()
