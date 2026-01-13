# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

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
from greenbone.scap_sync.utils.time import now, sub_days
from tests.tags import Integration_test


@Integration_test
class TestScapSync(unittest.IsolatedAsyncioTestCase):
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
        await self.db.dispose()
        self.postgres.stop()

    async def test_scap_sync_without_data(self):
        """Scap-sync should default to a 1day sync without any last_modified data"""

        # Arrange
        min_last_modified = sub_days(now(), 1)

        # Act
        await main_async()

        # Assert
        async with self.db.connect() as conn:
            res = await conn.execute(func.max(CVEModel.last_modified))
            last_mod_cve = res.scalar_one()

            self.assertGreaterEqual(
                last_mod_cve,
                min_last_modified,
                "scap-sync should upserted cve's for the default time window",
            )

            res = await conn.execute(func.max(CPEModel.last_modified))
            last_mod_cpe = res.scalar_one()

            self.assertGreaterEqual(
                last_mod_cpe,
                min_last_modified,
                "scap-sync should upserted cpes for the default timewindow",
            )


if __name__ == "__main__":
    unittest.main()
