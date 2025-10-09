from typing import Optional

from openg2p_fastapi_common.context import dbengine
from openg2p_fastapi_common.models import BaseORMModelWithId
from sqlalchemy import String, Boolean
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column


class DepartmentORM(BaseORMModelWithId):
    __tablename__ = "departments"

    code: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    bridge_base_url: Mapped[str] = mapped_column(String, nullable=False)
    spar_base_url: Mapped[str] = mapped_column(String, nullable=False)
    pbms_base_url: Mapped[str] = mapped_column(String, nullable=False)
    registry_base_url: Mapped[str] = mapped_column(String, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    @classmethod
    async def get_all_active(cls) -> list["DepartmentORM"]:
        """
        Get all active departments.
        """
        async_session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with async_session_maker() as session:
            from sqlalchemy import select

            result = await session.execute(select(cls).where(cls.active is True))
            return result.scalars().all()

    @classmethod
    async def get_by_code(cls, code: str) -> Optional["DepartmentORM"]:
        """
        Get department by code.
        """
        async_session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with async_session_maker() as session:
            from sqlalchemy import select

            result = await session.execute(
                select(cls).where(cls.code == code, cls.active is True)
            )
            return result.scalar_one_or_none()
