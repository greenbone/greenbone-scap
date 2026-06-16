# SPDX-FileCopyrightText: 2025 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import asyncio
import unittest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

from rich.console import Console
from rich.progress import Progress

from greenbone.scap.cli import DEFAULT_VERBOSITY, CLIError
from greenbone.scap.cpe_match.cli.processor import CpeMatchProcessor
from greenbone.scap.cpe_match.db.manager import CPEMatchStringDatabaseManager
from greenbone.scap.cpe_match.db.models import (
    CPEMatchDatabaseModel,
    CPEMatchStringDatabaseModel,
)
from greenbone.scap.cpe_match.producer.db import CpeMatchDatabaseProducer
from tests.cpe_match.producer.mock_worker import CpeMatchMockWorker
from tests.cpe_match.worker.mock_producer import (
    generate_cpe_name,
    uuid_replace,
    uuid_replace_str,
)
from tests.tags import Unit_test


def parse_worker_args(raw_args):
    parser = argparse.ArgumentParser()
    CpeMatchProcessor.add_args_to_parser(
        parser
    )  # for common args like "verbose"

    CpeMatchDatabaseProducer.add_args_to_parser(parser)
    return parser.parse_args(raw_args)


@Unit_test
class ParseArgsTestCase(unittest.TestCase):
    @patch(
        "greenbone.scap.cpe_match.producer.db.CpeMatchDatabaseProducer",
        autospec=True,
    )
    def test_defaults(self, mock_worker_init: MagicMock):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        args = parse_worker_args([])
        CpeMatchDatabaseProducer.from_args(
            args, console, error_console, progress
        )

        mock_worker_init.assert_called_once_with(
            console=console,
            error_console=error_console,
            progress=progress,
            database_name=None,
            database_schema=None,
            database_host=None,
            database_port=None,
            database_user=None,
            database_password=None,
            echo_sql=False,
            verbose=DEFAULT_VERBOSITY,
        )

    @patch(
        "greenbone.scap.cpe_match.producer.db.CpeMatchDatabaseProducer",
        autospec=True,
    )
    def test_database(self, mock_worker_init: MagicMock):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        args = parse_worker_args(
            [
                "--database-name",
                "test-db-name",
                "--database-schema",
                "test-db-schema",
                "--database-host",
                "test-db-host",
                "--database-port",
                "12345",
                "--database-user",
                "test-db-user",
                "--database-password",
                "test-db-password",
            ]
        )
        CpeMatchDatabaseProducer.from_args(
            args, console, error_console, progress
        )

        mock_worker_init.assert_called_once_with(
            console=console,
            error_console=error_console,
            progress=progress,
            database_name="test-db-name",
            database_schema="test-db-schema",
            database_host="test-db-host",
            database_port=12345,
            database_user="test-db-user",
            database_password="test-db-password",
            echo_sql=False,
            verbose=DEFAULT_VERBOSITY,
        )

    @patch(
        "greenbone.scap.cpe_match.producer.db.CpeMatchDatabaseProducer",
        autospec=True,
    )
    def test_echo_sql(self, mock_worker_init: MagicMock):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        args = parse_worker_args(["--echo-sql"])
        CpeMatchDatabaseProducer.from_args(
            args, console, error_console, progress
        )

        mock_worker_init.assert_called_once_with(
            console=console,
            error_console=error_console,
            progress=progress,
            database_name=None,
            database_schema=None,
            database_host=None,
            database_port=None,
            database_user=None,
            database_password=None,
            echo_sql=True,
            verbose=DEFAULT_VERBOSITY,
        )


@Unit_test
class InitTestCase(unittest.TestCase):
    def test_missing_user(self):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        with self.assertRaises(CLIError):
            CpeMatchDatabaseProducer(
                console=console,
                error_console=error_console,
                progress=progress,
                database_name=None,
                database_schema=None,
                database_host=None,
                database_port=None,
                database_user=None,
                database_password=None,
            )

    def test_missing_password(self):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        with self.assertRaises(CLIError):
            CpeMatchDatabaseProducer(
                console=console,
                error_console=error_console,
                progress=progress,
                database_name=None,
                database_schema=None,
                database_host=None,
                database_port=None,
                database_user="db-test-user",
                database_password=None,
            )

    @patch(
        "greenbone.scap.generic_cli.producer.db.PostgresDatabase", autospec=True
    )
    def test_database_defaults(self, db_mock: MagicMock):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        CpeMatchDatabaseProducer(
            console=console,
            error_console=error_console,
            progress=progress,
            database_name=None,
            database_schema=None,
            database_host=None,
            database_port=None,
            database_user="db-test-user",
            database_password="db-test-password",
        )

        db_mock.assert_called_with(
            user="db-test-user",
            password="db-test-password",
            host="localhost",
            port=5432,
            dbname="scap",
            schema=None,
            echo=False,
        )

    @patch(
        "greenbone.scap.generic_cli.producer.db.PostgresDatabase", autospec=True
    )
    def test_database_custom(self, db_mock: MagicMock):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        CpeMatchDatabaseProducer(
            console=console,
            error_console=error_console,
            progress=progress,
            database_name="db-test-name",
            database_schema="db-test-schema",
            database_host="db-test-host",
            database_port=12345,
            database_user="db-test-user",
            database_password="db-test-password",
        )

        db_mock.assert_called_with(
            user="db-test-user",
            password="db-test-password",
            host="db-test-host",
            port=12345,
            dbname="db-test-name",
            schema="db-test-schema",
            echo=False,
        )

    @patch(
        "greenbone.scap.generic_cli.producer.db.PostgresDatabase", autospec=True
    )
    def test_echo_sql(self, db_mock: MagicMock):
        console = Console()
        error_console = Console()
        progress = Progress()

        CpeMatchDatabaseProducer(
            console=console,
            error_console=error_console,
            progress=progress,
            database_name=None,
            database_schema=None,
            database_host=None,
            database_port=None,
            database_user="db-test-user",
            database_password="db-test-password",
            echo_sql=True,
        )

        db_mock.assert_called_with(
            user="db-test-user",
            password="db-test-password",
            host="localhost",
            port=5432,
            dbname="scap",
            schema=None,
            echo=True,
        )


async def async_generate_db_cpe_match_strings(
    num_match_strings: int,
    base_match_criteria_id: UUID,
    base_cpe_name_id: UUID,
):
    for i in range(num_match_strings):
        match_criteria_id = uuid_replace_str(base_match_criteria_id, 1, i)
        cpe_name = generate_cpe_name(1, i)
        cpe_name_id = uuid_replace_str(base_cpe_name_id, 1, i)

        now = datetime.now()
        new_match_model = CPEMatchDatabaseModel()
        new_match_model.cpe_name = cpe_name
        new_match_model.cpe_name_id = cpe_name_id

        new_model = CPEMatchStringDatabaseModel()
        new_model.match_criteria_id = match_criteria_id
        new_model.criteria = cpe_name
        new_model.last_modified = now
        new_model.cpe_last_modified = now - timedelta(days=-1)
        new_model.created = now - timedelta(days=-2)
        new_model.status = "Active"
        new_model.matches = [new_match_model]

        yield new_model


@Unit_test
class ProduceTestCase(unittest.IsolatedAsyncioTestCase):
    NUM_CHUNKS = 5
    CHUNK_SIZE = 3
    QUEUE_SIZE = 2

    @patch(
        "greenbone.scap.generic_cli.producer.db.PostgresDatabase", autospec=True
    )
    @patch.object(CPEMatchStringDatabaseManager, "count")
    @patch.object(CPEMatchStringDatabaseManager, "all")
    async def test_read_from_db(
        self, all_mock: AsyncMock, count_mock: AsyncMock, db_mock: AsyncMock
    ):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        producer = CpeMatchDatabaseProducer(
            console=console,
            error_console=error_console,
            progress=progress,
            database_name="test-db-name",
            database_schema="test-db-name",
            database_host="test-db-host",
            database_port=12345,
            database_user="test-db-user",
            database_password="test-db-password",
        )
        worker = CpeMatchMockWorker(
            console=console,
            error_console=error_console,
            progress=progress,
        )
        processor = CpeMatchProcessor(
            console,
            error_console,
            producer,
            worker,
            queue_size=self.QUEUE_SIZE,
            chunk_size=self.CHUNK_SIZE,
        )
        EXPECTED_COUNT = self.NUM_CHUNKS * self.CHUNK_SIZE
        count_mock.return_value = EXPECTED_COUNT

        base_match_criteria_id = uuid4()
        base_cpe_name_id = uuid4()
        all_mock.return_value = async_generate_db_cpe_match_strings(
            EXPECTED_COUNT,
            base_match_criteria_id,
            base_cpe_name_id,
        )

        async with asyncio.timeout(10):
            await processor.run()

            db_mock.assert_called_once_with(
                dbname="test-db-name",
                schema="test-db-name",
                host="test-db-host",
                port=12345,
                user="test-db-user",
                password="test-db-password",
                echo=False,
            )

        self.assertEqual(EXPECTED_COUNT, worker.item_count)

        for i in range(EXPECTED_COUNT):
            expected_match_criteria_id = uuid_replace(
                base_match_criteria_id, 1, i
            )
            expected_cpe_name_id = uuid_replace(base_cpe_name_id, 1, i)
            expected_cpe_name = generate_cpe_name(1, i)

            match_string = worker.items_received[i]
            self.assertEqual(
                expected_match_criteria_id, match_string.match_criteria_id
            )
            self.assertIsInstance(expected_cpe_name_id, UUID)
            self.assertEqual(expected_cpe_name, match_string.criteria)
            self.assertIsInstance(match_string.created, datetime)
            self.assertIsInstance(match_string.last_modified, datetime)
            self.assertIsInstance(match_string.cpe_last_modified, datetime)
            self.assertEqual(
                expected_cpe_name_id, match_string.matches[0].cpe_name_id
            )
            self.assertIsInstance(match_string.matches[0].cpe_name_id, UUID)
            self.assertEqual(
                expected_cpe_name, match_string.matches[0].cpe_name
            )
