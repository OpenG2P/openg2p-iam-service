import json
from datetime import date, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Date, DateTime, func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from iam_core.models import LoginProvider
from openg2p_fastapi_common.context import dbengine

from ..models import (
    StaffApplicationPermission,
    StaffPortalApplication,
    StaffRole,
    StaffRolePermission,
)


class DataLoader:
    def __init__(self):
        self._data_dir = Path(__file__).resolve().parent

    def load_login_providers(self) -> list[dict[str, Any]]:
        return self._load_dataset("login_providers.json")

    def load_staff_portal_applications(self) -> list[dict[str, Any]]:
        return self._load_dataset("staff_portal_applications.json")

    def load_staff_roles(self) -> list[dict[str, Any]]:
        return self._load_dataset("staff_roles.json")

    def load_staff_application_permissions(self) -> list[dict[str, Any]]:
        return self._load_dataset("staff_application_permissions.json")

    def load_staff_role_permissions(self) -> list[dict[str, Any]]:
        return self._load_dataset("staff_role_permissions.json")

    def _load_dataset(
        self,
        default_filename: str,
    ) -> list[dict[str, Any]]:
        raw_value = (self._data_dir / default_filename).read_text(encoding="utf-8")

        try:
            payload = json.loads(raw_value)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON in {default_filename}: {exc.msg}"
            ) from exc

        if not isinstance(payload, list):
            raise ValueError(f"{default_filename} must be a JSON array of objects")

        if any(not isinstance(row, dict) for row in payload):
            raise ValueError(f"{default_filename} must contain only JSON objects")

        return payload


async def run_data_loader() -> None:
    loader = DataLoader()

    async_session = async_sessionmaker(dbengine.get(), expire_on_commit=False)
    async with async_session() as session:
        await _seed_if_empty(session, LoginProvider, loader.load_login_providers())
        await _seed_if_empty(
            session,
            StaffPortalApplication,
            loader.load_staff_portal_applications(),
        )
        await _seed_if_empty(session, StaffRole, loader.load_staff_roles())
        await _seed_if_empty(
            session,
            StaffApplicationPermission,
            loader.load_staff_application_permissions(),
        )
        await _seed_if_empty(
            session,
            StaffRolePermission,
            loader.load_staff_role_permissions(),
        )
        await session.commit()


async def _seed_if_empty(
    session: AsyncSession,
    model,
    rows: list[dict],
) -> None:
    row_count = await session.scalar(select(func.count()).select_from(model))
    if row_count and row_count > 0:
        return

    if not rows:
        return

    await session.execute(insert(model), _coerce_rows_for_model(model, rows))


def _coerce_rows_for_model(model, rows: list[dict]) -> list[dict]:
    datetime_columns: set[str] = set()
    date_columns: set[str] = set()

    for column in model.__table__.columns:
        if isinstance(column.type, DateTime):
            datetime_columns.add(column.name)
        elif isinstance(column.type, Date):
            date_columns.add(column.name)

    coerced_rows: list[dict] = []
    for row in rows:
        coerced = dict(row)

        for column_name in datetime_columns:
            # Let ORM/DB defaults populate timestamp audit fields.
            if column_name in {"created_at", "updated_at"}:
                coerced.pop(column_name, None)
                continue

            value = coerced.get(column_name)
            if isinstance(value, str):
                coerced[column_name] = datetime.fromisoformat(value)

        for column_name in date_columns:
            value = coerced.get(column_name)
            if isinstance(value, str):
                coerced[column_name] = date.fromisoformat(value)

        coerced_rows.append(coerced)

    return coerced_rows
