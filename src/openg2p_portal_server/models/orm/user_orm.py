from datetime import date
from typing import Optional
from enum import Enum

from openg2p_fastapi_common.context import dbengine
from openg2p_fastapi_common.models import BaseORMModelWithId
from openg2p_fastapi_common.errors.http_exceptions import InternalServerError
from sqlalchemy import Date, String, ForeignKey, select, text, Enum as SQLEnum
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from ..user_schemas import UserCreate


class UserType(Enum):
    BENEFICIARY = "beneficiary"
    STAFF = "staff"
    AGENCY = "agency"


class UserORM(BaseORMModelWithId):
    __tablename__ = "users"

    name: Mapped[str] = mapped_column(String(), nullable=False)
    gender: Mapped[Optional[str]] = mapped_column(String(), nullable=True)
    email: Mapped[Optional[str]] = mapped_column(String(), nullable=True)
    phone_number: Mapped[Optional[str]] = mapped_column(String(), nullable=True)

    unique_user_id: Mapped[str] = mapped_column(String(), unique=True, nullable=False)
    id_type: Mapped[Optional[str]] = mapped_column(String(), nullable=True)

    user_id: Mapped[Optional[str]] = mapped_column(String(), unique=True, nullable=True)
    user_type: Mapped[Optional[UserType]] = mapped_column(
        SQLEnum(UserType, name="user_type_enum"),
        nullable=True,
    )

    birthdate: Mapped[Optional[date]] = mapped_column(Date(), nullable=True)

    auth_provider_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("auth_oauth_provider.id", ondelete="SET NULL"),
        nullable=True,
    )

    @classmethod
    async def get_user_by_id(cls, user_id: int) -> Optional["UserORM"]:
        async_session_maker = async_sessionmaker(dbengine.get())
        async with async_session_maker() as session:
            stmt = select(cls).filter(cls.id == user_id)
            result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @classmethod
    async def get_user_by_unique_user_id(
        cls, unique_user_id: str
    ) -> Optional["UserORM"]:
        async_session_maker = async_sessionmaker(dbengine.get())
        async with async_session_maker() as session:
            stmt = select(cls).filter(cls.unique_user_id == unique_user_id)
            result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @classmethod
    async def get_user_by_user_id(cls, user_id: str) -> Optional["UserORM"]:
        async_session_maker = async_sessionmaker(dbengine.get())
        async with async_session_maker() as session:
            stmt = select(cls).filter(cls.user_id == user_id)
            result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @classmethod
    async def create_user(cls, user_create: UserCreate) -> Optional["UserORM"]:
        async_session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with async_session_maker() as session:
            user: UserORM = cls(**user_create.model_dump(), active=True)
            session.add(user)
            try:
                await session.commit()
                await session.refresh(user)
                return user
            except IntegrityError as e:
                await session.rollback()
                raise InternalServerError(
                    message=f"Could not create user: {repr(e)}"
                ) from e

    @classmethod
    async def get_user_fields(cls) -> list[str]:
        async_session_maker = async_sessionmaker(dbengine.get())
        async with async_session_maker() as session:
            result = await session.execute(
                text(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = :tbl_name"
                ),
                params={"tbl_name": cls.__tablename__},
            )
        return result.scalars().all()
