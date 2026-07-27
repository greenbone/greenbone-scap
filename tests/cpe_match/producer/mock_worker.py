# SPDX-FileCopyrightText: 2025 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later
from collections.abc import Sequence

from pontos.nvd.models.cpe_match_string import CPEMatchString
from rich.console import Console
from rich.progress import Progress

from greenbone.scap.generic_cli.worker.base import BaseScapWorker


class CpeMatchMockWorker(BaseScapWorker[CPEMatchString]):
    def __init__(
        self,
        console: Console,
        error_console: Console,
        progress: Progress,
        *,
        verbose: int | None = None,
    ):
        super().__init__(
            console=console,
            error_console=error_console,
            progress=progress,
            verbose=verbose,
        )
        self.context_entered: bool = False
        self.context_exited: bool = False
        self.items_received: list[CPEMatchString] = []
        self.item_count = 0
        self.chunk_count = 0

    async def _handle_chunk(self, chunk: Sequence[CPEMatchString]) -> None:
        self.items_received.extend(chunk)
        self.item_count += len(chunk)
        self.chunk_count += 1

    async def __aenter__(self):
        self.context_entered = True

    async def __aexit__(self, /, __exc_type, __exc_value, __traceback):
        self.context_exited = True
