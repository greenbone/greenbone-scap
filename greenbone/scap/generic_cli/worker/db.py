# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import os
from abc import abstractmethod
from argparse import ArgumentParser
from typing import AsyncContextManager, Sequence, Type, TypeVar

from rich.console import Console
from rich.progress import Progress

from ...cli import (
    DEFAULT_POSTGRES_DATABASE_NAME,
    DEFAULT_POSTGRES_HOST,
    DEFAULT_POSTGRES_PORT,
    DEFAULT_VERBOSITY,
    CLIError,
)
from ...db import PostgresDatabase
from .base import BaseScapWorker

T = TypeVar("T")
"Generic type variable for the type of SCAP items handled"


class ScapDatabaseWriteWorker(BaseScapWorker[T]):
    """
    Abstract async context manager base class for a worker writing
    SCAP items to a single JSON file.

    The type of the SCAP items is to be specified by the generic type,
    e.g. `ScapJsonWriteWorker[CPE]` will be a producer handling CPE objects.

    Attributes:
        _item_type_plural: Plural form of the type of items to use in
         log messages (class attribute).
        _arg_defaults: Default values for optional arguments
         (class attribute).
        _console: Console for standard output.
        _error_console: Console for error output.
        _progress: Progress bar renderer to be updated by the producer.
        _verbose: Verbosity level of log messages.
        _database: Database connection handler.
        _manager: SCAP item database manager.
    """

    _item_type_plural = BaseScapWorker._item_type_plural
    "Plural form of the type of items to use in log messages."

    _arg_defaults = {
        "database_name": DEFAULT_POSTGRES_DATABASE_NAME,
        "database_host": DEFAULT_POSTGRES_HOST,
        "database_port": DEFAULT_POSTGRES_PORT,
        "database_schema": None,
        "verbose": DEFAULT_VERBOSITY,
    }
    "Default values for optional arguments."

    @classmethod
    def add_args_to_parser(
        cls: Type["ScapDatabaseWriteWorker"],
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
            f"\"{cls._arg_defaults['database_name']}\" if not set.",
        )
        db_group.add_argument(
            "--database-host",
            help=f"Name of the {cls._item_type_plural} database host. "
            f"Uses environment variable DATABASE_HOST or "
            f"\"{cls._arg_defaults['database_host']}\" if not set.",
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
            f"\"{cls._arg_defaults['database_schema']}\" if not set.",
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
            host=database_host,
            port=database_port,
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
    async def _handle_chunk(self, chunk: Sequence[T]) -> None:
        """
        Handles a chunk of SCAP items from the queue.

        Args:
            chunk: The last chunk fetched from the queue.
        """
        pass

    @abstractmethod
    def _create_manager(self) -> AsyncContextManager:
        """
        Callback creating a new database manager for handling SCAP items.

        Returns: The new database manager.
        """
        pass

    async def _loop_start(self) -> None:
        """
        Callback handling the start of the loop fetching and processing the SCAP items.
        """
        if self._verbose:
            self._console.log("Initialized database.")
        await super()._loop_start()

    async def __aenter__(self):
        await self._database.__aenter__()
        await self._manager.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        db_ret = await self._database.__aexit__(exc_type, exc_val, exc_tb)
        manager_ret = await self._manager.__aexit__(exc_type, exc_val, exc_tb)
        return db_ret or manager_ret
