# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import os
from abc import abstractmethod
from argparse import ArgumentParser
from typing import AsyncContextManager, Sequence, TypeVar

from rich.console import Console
from rich.progress import Progress

from ...cli import (
    DEFAULT_POSTGRES_DATABASE_NAME,
    DEFAULT_POSTGRES_HOST,
    DEFAULT_POSTGRES_PORT,
    CLIError,
)
from ...db import PostgresDatabase
from .base import BaseScapWorker

T = TypeVar("T")


class ScapDatabaseWriteWorker(BaseScapWorker[T]):
    item_type_plural = BaseScapWorker.item_type_plural
    arg_defaults = {
        "database_name": DEFAULT_POSTGRES_DATABASE_NAME,
        "database_host": DEFAULT_POSTGRES_HOST,
        "database_port": DEFAULT_POSTGRES_PORT,
        "database_schema": None,
    }

    @classmethod
    def add_args_to_parser(
        cls: type,
        parser: ArgumentParser,
    ):
        db_group = parser.add_argument_group(
            title="Database", description="Database related settings"
        )

        db_group.add_argument(
            "--database-name",
            help=f"Name of the {cls.item_type_plural} database. "
            f"Uses environment variable DATABASE_NAME or "
            f"\"{cls.arg_defaults['database_name']}\" if not set.",
        )
        db_group.add_argument(
            "--database-host",
            help=f"Name of the {cls.item_type_plural} database host. "
            f"Uses environment variable DATABASE_HOST or "
            f"\"{cls.arg_defaults['database_host']}\" if not set.",
        )

        db_group.add_argument(
            "--database-port",
            help=f"Port for the {cls.item_type_plural} database. "
            f"Uses environment variable DATABASE_PORT or "
            f"{cls.arg_defaults['database_port']} if not set.",
            type=int,
        )
        db_group.add_argument(
            "--database-user",
            help=f"Name of the {cls.item_type_plural} database user. "
            f"Uses environment variable DATABASE_USER if not set.",
        )
        db_group.add_argument(
            "--database-password",
            help=f"Name of the {cls.item_type_plural} database password. "
            f"Uses environment variable DATABASE_PASSWORD if not set.",
        )
        db_group.add_argument(
            "--database-schema",
            help=f"Name of the {cls.item_type_plural} database schema. "
            f"Uses environment variable DATABASE_SCHEMA or "
            f"\"{cls.arg_defaults['database_schema']}\" if not set.",
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
        verbose: int = arg_defaults,
    ):
        super().__init__(console, error_console, progress, verbose=verbose)

        database_name = (
            database_name
            or os.environ.get("DATABASE_NAME")
            or self.arg_defaults["database_name"]
        )
        database_schema = (
            database_schema
            or os.environ.get("DATABASE_SCHEMA")
            or self.arg_defaults["database_schema"]
        )
        database_host = (
            database_host
            or os.environ.get("DATABASE_HOST")
            or self.arg_defaults["database_host"]
        )
        try:
            env_database_port = int(os.environ.get("DATABASE_PORT"))
        except TypeError:
            env_database_port = None
        database_port = (
            database_port
            or env_database_port
            or self.arg_defaults["database_port"]
        )
        database_user = database_user or os.environ.get("DATABASE_USER")
        database_password = database_password or os.environ.get(
            "DATABASE_PASSWORD"
        )

        if not database_user:
            raise CLIError(f"Missing user for {self.item_type_plural} database")

        if not database_password:
            raise CLIError(
                f"Missing password for {self.item_type_plural} database"
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
    async def add_chunk(self, chunk: Sequence[T]) -> None:
        pass

    @abstractmethod
    def _create_manager(self) -> AsyncContextManager:
        pass

    async def loop_start(self) -> None:
        if self.verbose:
            self.console.log("Initialized database.")
        await super().loop_start()

    async def __aenter__(self):
        await self._database.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        db_ret = await self._database.__aexit__(exc_type, exc_val, exc_tb)
        manager_ret = await self._manager.__aexit__(exc_type, exc_val, exc_tb)
        return db_ret or manager_ret
