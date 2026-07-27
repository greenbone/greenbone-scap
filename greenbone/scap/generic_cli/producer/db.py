# SPDX-FileCopyrightText: 2025 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import os
from abc import abstractmethod
from argparse import ArgumentParser
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager
from typing import (
    Generic,
    TypeVar,
)

from rich.console import Console
from rich.progress import Progress

from greenbone.scap.cli import (
    DEFAULT_POSTGRES_DATABASE_NAME,
    DEFAULT_POSTGRES_HOST,
    DEFAULT_POSTGRES_PORT,
    DEFAULT_VERBOSITY,
    CLIError,
)
from greenbone.scap.cpe_match.db.models import BaseDatabaseModel
from greenbone.scap.generic_cli.producer.base import BaseScapProducer

from ...db import PostgresDatabase
from ...timer import Timer

T = TypeVar("T")
"Generic type variable for the type of SCAP items handled"


class DatabaseProducer(BaseScapProducer, Generic[T]):
    """
    Abstract async context manager base class for a producer querying
    SCAP items from a PostgreSQL database.

    The type of items is to be defined by the generic type T in subclasses.
    """

    _item_type_plural = BaseScapProducer._item_type_plural
    "Plural form of the type of items to use in log messages"

    _arg_defaults = {  # noqa: RUF012
        "database_name": DEFAULT_POSTGRES_DATABASE_NAME,
        "database_host": DEFAULT_POSTGRES_HOST,
        "database_port": DEFAULT_POSTGRES_PORT,
        "database_schema": None,
        "verbose": DEFAULT_VERBOSITY,
    }
    "Default values for optional arguments."

    @classmethod
    def add_args_to_parser(
        cls: type["DatabaseProducer"],
        parser: ArgumentParser,
    ):
        """
        Class method for adding database writer arguments to an
         `ArgumentParser`.

        Args:
            parser: The parser to add the arguments to.
        """
        db_group = parser.add_argument_group(
            title="Database", description="Database related settings"
        )

        db_group.add_argument(
            "--database-name",
            help=f"Name of the {cls._item_type_plural} database. "
            f"Uses environment variable DATABASE_NAME or "
            f'"{cls._arg_defaults["database_name"]}" if not set.',
        )
        db_group.add_argument(
            "--database-host",
            help=f"Name of the {cls._item_type_plural} database host. "
            f"Uses environment variable DATABASE_HOST or "
            f'"{cls._arg_defaults["database_host"]}" if not set.',
        )

        db_group.add_argument(
            "--database-port",
            help=f"Port for the {cls._item_type_plural} database. "
            f"Uses environment variable DATABASE_PORT or "
            f"{cls._arg_defaults['database_port']} if not set.",
            type=int,
        )
        db_group.add_argument(
            "--database-user",
            help=f"Name of the {cls._item_type_plural} database user. "
            f"Uses environment variable DATABASE_USER if not set.",
        )
        db_group.add_argument(
            "--database-password",
            help=f"Name of the {cls._item_type_plural} database password. "
            f"Uses environment variable DATABASE_PASSWORD if not set.",
        )
        db_group.add_argument(
            "--database-schema",
            help=f"Name of the {cls._item_type_plural} database schema. "
            f"Uses environment variable DATABASE_SCHEMA or "
            f'"{cls._arg_defaults["database_schema"]}" if not set.',
        )
        db_group.add_argument(
            "--echo-sql",
            action="store_true",
            help="Print out all SQL queries.",
        )

    def __init__(
        self,
        console: Console,
        error_console: Console,
        progress: Progress,
        *,
        database_name: str | None,
        database_schema: str | None,
        database_host: str | None,
        database_port: int | None,
        database_user: str | None,
        database_password: str | None,
        echo_sql: bool = False,
        verbose: int = _arg_defaults["verbose"],
    ):
        """
        Constructor for a SCAP database write worker.

        If the `database_...` arguments are None or not given, corresponding
        environment variables will be tried next before finally using the
        defaults as a fallback.

        Args:
            console: Console for standard output.
            error_console: Console for error output.
            progress: Progress bar renderer to be updated by the producer.
            database_name: Name of the database to use.
            database_schema: Optional database schema to use.
            database_host: IP address or hostname of the database server to use.
            database_port: Port of the database server to use.
            database_user: Name of the database user to use.
            database_password: Password of the database user to use.
            echo_sql: Whether to print SQL statements.
            verbose: Verbosity level of log messages.
        """
        super().__init__(console, error_console, progress, verbose=verbose)

        database_name = (
            database_name
            or os.environ.get("DATABASE_NAME")
            or self._arg_defaults["database_name"]
        )
        database_schema = (
            database_schema
            or os.environ.get("DATABASE_SCHEMA")
            or self._arg_defaults["database_schema"]
        )
        database_host = (
            database_host
            or os.environ.get("DATABASE_HOST")
            or self._arg_defaults["database_host"]
        )
        try:
            port_str = os.environ.get("DATABASE_PORT")
            env_database_port = int(port_str) if port_str else None
        except TypeError:
            env_database_port = None
        database_port = (
            database_port
            or env_database_port
            or self._arg_defaults["database_port"]
        )
        database_user = database_user or os.environ.get("DATABASE_USER")
        database_password = database_password or os.environ.get(
            "DATABASE_PASSWORD"
        )

        if not database_user:
            raise CLIError(
                f"Missing user for {self._item_type_plural} database"
            )

        if not database_password:
            raise CLIError(
                f"Missing password for {self._item_type_plural} database"
            )

        self._database = PostgresDatabase(
            user=database_user,
            password=database_password,
            host=database_host,  # type: ignore
            port=database_port,  # type: ignore
            dbname=database_name,  # type: ignore
            schema=database_schema,
            echo=echo_sql,
        )
        if verbose:
            console.log(f"Using PostgreSQL database {database_name}")
        if verbose >= 2:
            console.log(
                f"Database host: {database_host}, port: {database_port}, "
                f"schema: {database_schema}, user: {database_user}"
            )

        self._manager = self._create_manager()

    @abstractmethod
    def _create_manager(self) -> AbstractAsyncContextManager:
        """
        Callback creating a new database manager for handling SCAP items.

        Returns: The new database manager.
        """

    @abstractmethod
    def _convert_db_model(self, db_model: BaseDatabaseModel) -> T:
        """
        Callback converting a SCAP database model to a Pontos model.

        Args:
            db_model: The database model convert

        Returns:
            The converted model object.
        """

    @abstractmethod
    async def _db_item_count(self) -> int:
        """
        Callback getting the total number of SCAP items in the database.

        Returns:
            The total number of items
        """

    @abstractmethod
    def _db_item_iter(self) -> AsyncIterator[BaseDatabaseModel]:
        """
        Callback getting an async iterator of database items to process.

        Returns:
            An async iterator over database items.
        """

    async def fetch_initial_data(self) -> int:
        """
        Ensures any remaining initializations of the data source are done,
         so it can be queried for chunks of SCAP items by `run_loop`.
        It must also return the expected total number of items that will be
         fetched.

        Returns:
            The expected total number of items.
        """
        count = await self._db_item_count()
        self._console.log(
            f"{count:,} {self._item_type_plural} available in database"
        )
        return count

    async def run_loop(self) -> None:
        """
        Run a loop fetching chunks of SCAP items and adding them to the queue.

        The method must also call `set_producer_finished` before returning to signal
        that no more chunks will be added to the queue.

        It should also create a task for the `progress` object and update it
        regularly.
        """
        task = self._progress.add_task(
            f"Querying {self._item_type_plural}",
            total=self._queue.total_items,
        )
        count = 0

        try:
            with Timer() as query_timer:
                chunk = []
                async for db_item in self._db_item_iter():
                    item: T = self._convert_db_model(db_item)
                    chunk.append(item)
                    if len(chunk) >= self._queue.chunk_size:
                        count += len(chunk)
                        await self._queue.put_chunk(chunk)
                        chunk = []
                    self._progress.update(task, completed=count)

                count += len(chunk)
                if len(chunk):
                    await self._queue.put_chunk(chunk)
                self._progress.update(task, completed=count)

            self._console.log(
                f"Queried {count:,} {self._item_type_plural} in "
                f"{query_timer.elapsed_time:0.4f} seconds."
            )

        finally:
            # signal worker that we are finished with querying the DB
            self._queue.set_producer_finished()

    async def __aenter__(self):
        await self._database.__aenter__()
        await self._manager.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        db_ret = await self._database.__aexit__(exc_type, exc_val, exc_tb)
        manager_ret = await self._manager.__aexit__(exc_type, exc_val, exc_tb)
        return db_ret or manager_ret
