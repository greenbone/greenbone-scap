# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import asyncio
import unittest
from unittest import mock
from unittest.mock import AsyncMock, MagicMock, patch

from rich.console import Console
from rich.progress import Progress

from greenbone.scap.cli import DEFAULT_VERBOSITY, CLIError
from greenbone.scap.cpe_match.cli.processor import CpeMatchProcessor
from greenbone.scap.cpe_match.db.models import CPEMatchStringDatabaseModel
from greenbone.scap.cpe_match.worker.db import CpeMatchDatabaseWriteWorker
from tests.cpe_match.worker.mock_producer import CpeMatchMockProducer


def parse_worker_args(raw_args):
    parser = argparse.ArgumentParser()
    CpeMatchProcessor.add_args_to_parser(
        parser
    )  # for common args like "verbose"

    CpeMatchDatabaseWriteWorker.add_args_to_parser(parser)
    return parser.parse_args(raw_args)


class ParseArgsTestCase(unittest.TestCase):
    @patch(
        "greenbone.scap.cpe_match.worker.db.CpeMatchDatabaseWriteWorker",
        autospec=True,
    )
    def test_defaults(self, mock_worker_init: MagicMock):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        args = parse_worker_args([])
        CpeMatchDatabaseWriteWorker.from_args(
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
        "greenbone.scap.cpe_match.worker.db.CpeMatchDatabaseWriteWorker",
        autospec=True,
    )
    #    @patch("greenbone.scap.db.PostgresDatabase", autospec=True)
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
        CpeMatchDatabaseWriteWorker.from_args(
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
        "greenbone.scap.cpe_match.worker.db.CpeMatchDatabaseWriteWorker",
        autospec=True,
    )
    def test_echo_sql(self, mock_worker_init: MagicMock):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        args = parse_worker_args(["--echo-sql"])
        CpeMatchDatabaseWriteWorker.from_args(
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


class InitTestCase(unittest.TestCase):
    def test_missing_user(self):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        with self.assertRaises(CLIError):
            CpeMatchDatabaseWriteWorker(
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
            CpeMatchDatabaseWriteWorker(
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
        "greenbone.scap.generic_cli.worker.db.PostgresDatabase", autospec=True
    )
    def test_database_defaults(self, db_mock: MagicMock):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        CpeMatchDatabaseWriteWorker(
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
        "greenbone.scap.generic_cli.worker.db.PostgresDatabase", autospec=True
    )
    def test_database_custom(self, db_mock: MagicMock):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        CpeMatchDatabaseWriteWorker(
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
        "greenbone.scap.generic_cli.worker.db.PostgresDatabase", autospec=True
    )
    def test_echo_sql(self, db_mock: MagicMock):
        console = Console()
        error_console = Console()
        progress = Progress()

        CpeMatchDatabaseWriteWorker(
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


class WriteTestCase(unittest.IsolatedAsyncioTestCase):
    NUM_CHUNKS = 5
    CHUNK_SIZE = 3
    QUEUE_SIZE = 2

    @patch(
        "greenbone.scap.generic_cli.worker.db.PostgresDatabase", autospec=True
    )
    async def test_write_json(self, db_mock: AsyncMock):
        console = Console(quiet=False)
        error_console = Console(quiet=False)
        progress = Progress(disable=True)

        producer = CpeMatchMockProducer(
            console=console,
            error_console=error_console,
            progress=progress,
            num_chunks=self.NUM_CHUNKS,
            chunk_size=self.CHUNK_SIZE,
        )
        worker = CpeMatchDatabaseWriteWorker(
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
        processor = CpeMatchProcessor(
            console,
            error_console,
            producer,
            worker,
            queue_size=self.QUEUE_SIZE,
            chunk_size=self.CHUNK_SIZE,
        )
        db_mock.insert.side_effect = lambda x: print("x=", x)

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
            # check if there is at least one insert call for each chunk
            insert_call = mock.call().insert(CPEMatchStringDatabaseModel)
            self.assertGreaterEqual(
                self.NUM_CHUNKS, db_mock.mock_calls.count(insert_call)
            )

            print(db_mock)
