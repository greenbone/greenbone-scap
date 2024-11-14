# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
from argparse import Namespace
from typing import Sequence, AsyncContextManager

from pontos.nvd.models.cpe_match_string import CPEMatchString
from rich.console import Console
from rich.progress import Progress

from ..cli.processor import CPE_MATCH_TYPE_PLURAL
from ..db.manager import CPEMatchStringDatabaseManager
from ...cli import DEFAULT_VERBOSITY
from ...generic_cli.worker.db import ScapDatabaseWriteWorker


class CpeMatchDatabaseWriteWorker(ScapDatabaseWriteWorker[CPEMatchString]):

    item_type_plural = CPE_MATCH_TYPE_PLURAL
    arg_defaults = ScapDatabaseWriteWorker.arg_defaults

    @classmethod
    def get_item_type_plural(cls):
        return "CPE Match Strings"

    @classmethod
    def from_args(
        cls,
        args: Namespace,
        console: Console,
        error_console: Console,
        progress: Progress,
    ) -> "CpeMatchDatabaseWriteWorker":

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

    async def add_chunk(self, chunk: Sequence[CPEMatchString]):
        await self._manager.add_cpe_match_strings(chunk)

    def _create_manager(self) -> AsyncContextManager:
        return CPEMatchStringDatabaseManager(self._database)
