from __future__ import annotations

import datetime as _dt

from sqlalchemy import func
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    create_async_engine,
)

from .env import ScapEnv


def create_async_db_from_env(env: ScapEnv) -> AsyncEngine:
    host = env["DATABASE_HOST"]
    port = env["DATABASE_PORT"]
    dbname = env["DATABASE_NAME"]
    user = env["DATABASE_USER"]
    password = env["DATABASE_PASSWORD"]
    echo = env["LOG_LEVEL"] == "debug"

    conn_str = (
        f"postgresql+psycopg_async://{user}:{password}@{host}:{port}/{dbname}"
    )
    db = create_async_engine(conn_str, echo=echo)

    return db


async def get_latest_last_modified(db: AsyncEngine, model) -> _dt.datetime:
    min_sync_date = _dt.datetime.now(_dt.timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    ) - _dt.timedelta(days=2)

    async with db.connect() as conn:
        res = await conn.execute(func.max(model.last_modified))
        last_modified = res.scalar()

        if not last_modified:
            last_modified = min_sync_date
            print(
                f"Warning: No last_modified found, defaulting to {last_modified}"
            )
        elif last_modified < min_sync_date:
            last_modified = min_sync_date
            print(
                f"Warning: last_modified too old, defaulting to {last_modified}"
            )

        return last_modified
