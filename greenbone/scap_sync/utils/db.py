from __future__ import annotations

import datetime as _dt

from sqlalchemy import func
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    create_async_engine,
)

from greenbone.scap_sync.utils.time import (
    start_of_today,
    sub_days,
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
    min_sync_date = sub_days(start_of_today(), 1)

    async with db.connect() as conn:
        res = await conn.execute(func.max(model.last_modified))
        last_modified = res.scalar()

        if not last_modified:
            last_modified = min_sync_date
            print(
                f"Warning: No last_modified found, defaulting to {min_sync_date}"
            )
        elif last_modified < min_sync_date:
            last_modified = min_sync_date
            print(
                f"Warning: last_modified too old, defaulting to {min_sync_date}"
            )

        return last_modified
