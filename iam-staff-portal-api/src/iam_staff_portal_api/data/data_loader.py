import json
import logging
from abc import ABC
from datetime import date, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Date, DateTime, func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from iam_core.models import LoginProvider
from openg2p_fastapi_common.context import dbengine

from ..config import Settings
from ..models import (
    StaffApplicationPermission,
    StaffPortalApplication,
    StaffRole,
    StaffRolePermission,
)

_logger = logging.getLogger("iam-staff-data-loader")


class DataLoaderBase(ABC):
    data_models = (
        LoginProvider,
        StaffPortalApplication,
        StaffRole,
        StaffApplicationPermission,
        StaffRolePermission,
    )

    def get_mounted_data_dir(self) -> Path:
        return Path(Settings.get_config(strict=False).data_dir)

    def get_fallback_data_dir(self) -> Path:
        return Path(__file__).resolve().parent

    def get_config(self) -> Settings:
        return Settings.get_config(strict=False)

    def get_dataset_path(self, model, data_dir: Path) -> Path:
        return data_dir / f"{model.__tablename__}.json"

    def load_dataset(
        self,
        model,
        data_dir: Path,
    ) -> list[dict[str, Any]]:
        dataset_path = self.get_dataset_path(model, data_dir)
        if not dataset_path.exists():
            return []

        raw_value = dataset_path.read_text(encoding="utf-8")

        try:
            payload = json.loads(raw_value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {dataset_path}: {exc.msg}") from exc

        if not isinstance(payload, list):
            raise ValueError(f"{dataset_path} must be a JSON array of objects")

        if any(not isinstance(row, dict) for row in payload):
            raise ValueError(f"{dataset_path} must contain only JSON objects")

        return self.apply_config_values(model, payload)

    def apply_config_values(
        self,
        model,
        rows: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if model is StaffPortalApplication:
            return self.apply_application_url_values(rows)

        if model is LoginProvider:
            return self.apply_login_provider_values(rows)

        return rows

    def apply_application_url_values(
        self,
        rows: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        application_urls = self.get_config().data_application_urls
        updated_rows: list[dict[str, Any]] = []

        for row in rows:
            updated_row = dict(row)
            application_url_key = updated_row.get("application_url")

            if application_url_key in application_urls:
                updated_row["application_url"] = application_urls[application_url_key]

            updated_rows.append(updated_row)

        return updated_rows

    def apply_login_provider_values(
        self,
        rows: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        client_secrets = self.get_config().data_client_secrets
        updated_rows: list[dict[str, Any]] = []

        for row in rows:
            updated_row = dict(row)
            client_secret_key = updated_row.get("client_secret")

            if client_secret_key in client_secrets:
                updated_row["client_secret"] = client_secrets[client_secret_key]

            updated_rows.append(updated_row)

        return updated_rows

    async def seed_models_from_dir(
        self,
        session: AsyncSession,
        data_dir: Path,
    ) -> None:
        if not data_dir.exists() or not data_dir.is_dir():
            _logger.info("Skipping missing data directory: %s", data_dir)
            return

        _logger.info("Loading data from %s", data_dir)

        for model in self.data_models:
            rows = self.load_dataset(model, data_dir)
            await self.seed_if_empty(session, model, rows)

    async def seed_if_empty(
        self,
        session: AsyncSession,
        model,
        rows: list[dict[str, Any]],
    ) -> None:
        row_count = await session.scalar(select(func.count()).select_from(model))
        if row_count and row_count > 0:
            return

        if not rows:
            return

        _logger.info("Seeding %s with %s rows", model.__tablename__, len(rows))
        await session.execute(insert(model), self.coerce_rows_for_model(model, rows))

    def coerce_rows_for_model(
        self,
        model,
        rows: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        datetime_columns: set[str] = set()
        date_columns: set[str] = set()

        for column in model.__table__.columns:
            if isinstance(column.type, DateTime):
                datetime_columns.add(column.name)
            elif isinstance(column.type, Date):
                date_columns.add(column.name)

        coerced_rows: list[dict[str, Any]] = []
        for row in rows:
            coerced = dict(row)

            for column_name in datetime_columns:
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

    def create_session_factory(self) -> async_sessionmaker[AsyncSession]:
        return async_sessionmaker(dbengine.get(), expire_on_commit=False)


class DataLoader(DataLoaderBase):
    @classmethod
    async def run(cls) -> None:
        loader = cls()
        session_factory = loader.create_session_factory()

        _logger.info("Starting IAM staff data loader")
        async with session_factory() as session:
            await loader.load_data(session)
            await loader.load_fallback_data(session)
            await session.commit()
        _logger.info("Completed IAM staff data loader")

    async def load_data(self, session: AsyncSession) -> None:
        await self.seed_models_from_dir(session, self.get_mounted_data_dir())

    async def load_fallback_data(self, session: AsyncSession) -> None:
        await self.seed_models_from_dir(session, self.get_fallback_data_dir())
