# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace
from typing import AsyncContextManager, Sequence

from pontos.nvd.models.cpe_match_string import CPEMatchString
from rich.console import Console
from rich.progress import Progress

from ...cli import DEFAULT_VERBOSITY
from ...generic_cli.worker.db import ScapDatabaseWriteWorker
from ..cli.processor import CPE_MATCH_TYPE_PLURAL
from ..db.manager import CPEMatchStringDatabaseManager


class CpeMatchDatabaseWriteWorker(ScapDatabaseWriteWorker[CPEMatchString]):
    _item_type_plural = CPE_MATCH_TYPE_PLURAL
    "Plural form of the type of items to use in log messages."

    _arg_defaults = ScapDatabaseWriteWorker._arg_defaults
    "Default values for optional arguments."

    @classmethod
    def from_args(
        cls,
        args: Namespace,
        console: Console,
        error_console: Console,
        progress: Progress,
    ) -> "CpeMatchDatabaseWriteWorker":
        """
        Create a new `CpeMatchDatabaseWriteWorker` with parameters from
         the given command line args gathered by an `ArgumentParser`.

        Args:
            args: Command line arguments to use
            console: Console for standard output.
            error_console: Console for error output.
            progress: Progress bar renderer to be updated by the worker.

        Returns:
            The new `CpeMatchDatabaseWriteWorker`.
        """
        return CpeMatchDatabaseWriteWorker(
            console,
            error_console,
            progress,
            database_name=args.database_name,
            database_schema=args.database_schema,
            database_host=args.database_host,
            database_port=args.database_port,
            database_user=args.database_user,
            database_password=args.database_password,
            echo_sql=args.echo_sql,
            verbose=args.verbose or 0,
        )

    def __init__(
        self,
        console: Console,
        error_console: Console,
        progress: Progress,
        *,
        database_name: str,
        database_schema: str,
        database_host: str,
        database_port: int,
        database_user: str,
        database_password: str,
        echo_sql: bool = False,
        verbose: int = DEFAULT_VERBOSITY,
    ):
        """
        Constructor for a CPE match string database write worker.

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
        self._manager: CPEMatchStringDatabaseManager

        super().__init__(
            console,
            error_console,
            progress,
            database_name=database_name,
            database_schema=database_schema,
            database_host=database_host,
            database_port=database_port,
            database_user=database_user,
            database_password=database_password,
            echo_sql=echo_sql,
            verbose=verbose,
        )

    async def _handle_chunk(self, chunk: Sequence[CPEMatchString]):
        """
        Handles a chunk of CPE match strings from the queue.

        Adds the match strings to the database using the manager.

        Args:
            chunk: The last chunk fetched from the queue.
        """
        await self._manager.add_cpe_match_strings(chunk)

    def _create_manager(self) -> AsyncContextManager:
        """
        Callback creating a new database manager for handling SCAP items.

        Returns: The new database manager.
        """
        return CPEMatchStringDatabaseManager(self._database)
