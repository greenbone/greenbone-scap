from __future__ import annotations

import os
import unittest

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine
from testcontainers.postgres import PostgresContainer

from greenbone.scap.cpe.models import CPEModel
from greenbone.scap.cve.models import CVEModel
from greenbone.scap_sync.main import main_async
from greenbone.scap_sync.utils.db import create_async_db_from_env
from greenbone.scap_sync.utils.env import read_envs


class TestMainAsync(unittest.IsolatedAsyncioTestCase):
    postgres: PostgresContainer
    db: AsyncEngine

    async def asyncSetUp(self):
        self.postgres = PostgresContainer("postgres:15-bookworm")
        self.postgres.start()
        os.environ["DATABASE_USER"] = self.postgres.username
        os.environ["DATABASE_PASSWORD"] = self.postgres.password
        os.environ["DATABASE_NAME"] = self.postgres.dbname
        os.environ["DATABASE_HOST"] = self.postgres.get_container_host_ip()
        os.environ["DATABASE_PORT"] = str(
            self.postgres.get_exposed_port(self.postgres.port)
        )

        env = read_envs()
        self.db = create_async_db_from_env(env)

        async with self.db.begin() as conn:
            await conn.run_sync(CPEModel.metadata.create_all)
            await conn.run_sync(CVEModel.metadata.create_all)

    async def asyncTearDown(self):
        self.postgres.stop()

    async def test_main_async_with_postgres_no_data(self):

        await main_async()

        async with self.db.connect() as conn:
            res = await conn.execute(select(func.count()).select_from(CVEModel))
            cnt = res.scalar_one()

            self.assertGreater(
                cnt,
                0,
                "scap-sync should upserted the cves of the last two days",
            )

            res = await conn.execute(select(func.count()).select_from(CPEModel))
            cnt = res.scalar_one()

            self.assertGreater(
                cnt, 0, "scap-sync should upserted cpes of the last two days"
            )


if __name__ == "__main__":
    unittest.main()
