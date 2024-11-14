# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
from argparse import Namespace
from typing import Sequence

from pontos.nvd.models.cpe_match_string import CPEMatchString
from rich.console import Console
from rich.progress import Progress

from ..cli.processor import CPE_MATCH_TYPE_PLURAL
from ..json import MatchStringJsonManager
from ...generic_cli.worker.json import ScapJsonWriteWorker


class CpeMatchJsonWriteWorker(ScapJsonWriteWorker[CPEMatchString]):

    item_type_plural = CPE_MATCH_TYPE_PLURAL
    arg_defaults = ScapJsonWriteWorker.arg_defaults

    @classmethod
    def from_args(
        cls,
        args: Namespace,
        console: Console,
        error_console: Console,
        progress: Progress,
    ) -> "CpeMatchJsonWriteWorker":

        return CpeMatchJsonWriteWorker(
            console,
            error_console,
            progress,
            storage_path=args.storage_path or cls.arg_defaults["storage_path"],
            schema_path=args.schema_path or cls.arg_defaults["schema_path"],
            compress=args.compress if not None else False,
            verbose=args.verbose or 0,
        )

    def __init__(
        self,
        console: Console,
        error_console: Console,
        progress: Progress,
        *,
        storage_path: Path,
        schema_path: Path | None = None,
        compress: bool = False,
        verbose: int | None = None,
    ):
        super().__init__(
            console,
            error_console,
            progress,
            storage_path=storage_path,
            schema_path=schema_path,
            compress=compress,
            verbose=verbose,
        )

        self.json_manager = MatchStringJsonManager(
            error_console,
            storage_path,
            compress=compress,
            schema_path=schema_path,
            raise_error_on_validation=False,
        )

    async def add_chunk(self, chunk: Sequence[CPEMatchString]):
        self.json_manager.add_match_strings(chunk)

    async def loop_end(self) -> None:
        self.json_manager.write()
        await super().loop_end()
