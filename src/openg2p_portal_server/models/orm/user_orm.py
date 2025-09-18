from datetime import date, datetime
from typing import Optional
import json

from openg2p_fastapi_common.context import dbengine
from openg2p_fastapi_common.models import BaseORMModelWithId
from sqlalchemy import Date, DateTime, String, Text, select, text, ForeignKey
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column


class UserTypeORM(BaseORMModelWithId):
    __tablename__ = "user_types"

    name: Mapped[str] = mapped_column(String(), unique=True, nullable=False)


class UserORM(BaseORMModelWithId):
    __tablename__ = "user"

    name: Mapped[str] = mapped_column(String(), nullable=False)
    gender: Mapped[Optional[str]] = mapped_column(String(), nullable=True)
    email: Mapped[Optional[str]] = mapped_column(String(), nullable=True)
    phone_number: Mapped[Optional[str]] = mapped_column(String(), nullable=True)
    individual_id: Mapped[str] = mapped_column(String(), unique=True, nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(String(), unique=True, nullable=True)
    user_type: Mapped[Optional[str]] = mapped_column(String(), nullable=True)

    birthdate: Mapped[Optional[date]] = mapped_column(Date(), nullable=True)

    address: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)

    create_date: Mapped[datetime] = mapped_column(DateTime(), default=datetime.utcnow)
    write_date: Mapped[datetime] = mapped_column(DateTime(), default=datetime.utcnow)

    auth_provider_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("auth_oauth_provider.id", ondelete="SET NULL"),
        nullable=True,
    )


    def set_address(self, address_dict: dict):
        """Store address as JSON string."""
        self.address = json.dumps(address_dict)

    def get_address(self) -> Optional[dict]:
        """Return address as dictionary."""
        if self.address:
            return json.loads(self.address)
        return None

    # @classmethod
    # async def get_user(cls, id: int):
    #     async_session_maker = async_sessionmaker(dbengine.get())
    #     async with async_session_maker() as session:
    #         stmt = select(cls).filter(cls.id == id)
    #         result = await session.execute(stmt)
    #     return result.scalar()

    @classmethod
    async def get_user_by_id(cls, user_id: int):
        async_session_maker = async_sessionmaker(dbengine.get())
        async with async_session_maker() as session:
            stmt = select(cls).filter(cls.id == user_id)
            result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @classmethod
    async def get_user_by_individual_id(cls, individual_id: str):
        async_session_maker = async_sessionmaker(dbengine.get())
        async with async_session_maker() as session:
            stmt = select(cls).filter(cls.individual_id == individual_id)
            result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @classmethod
    async def get_user_by_user_id(cls, user_id: str):
        async_session_maker = async_sessionmaker(dbengine.get())
        async with async_session_maker() as session:
            stmt = select(cls).filter(cls.user_id == user_id)
            result = await session.execute(stmt)
        return result.scalar_one_or_none()
    

    @classmethod
    async def get_user_fields(cls):
        async_session_maker = async_sessionmaker(dbengine.get())
        async with async_session_maker() as session:
            result = await session.execute(
                text(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = :tbl_name"
                ),
                params={"tbl_name": cls.__tablename__},
            )
        return result.scalars().all()
