# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
from abc import ABC, abstractmethod
from argparse import ArgumentParser
from typing import Generic, TypeVar, Sequence, AsyncContextManager

from rich.console import Console
from rich.progress import Progress, TaskID

from ..queue import ScapChunkQueue

from ...cli import DEFAULT_VERBOSITY
from ...errors import ScapError

T = TypeVar("T")


class BaseScapWorker(Generic[T], AsyncContextManager, ABC):

    item_type_plural = "SCAP items"
    arg_defaults = {
        "verbose": DEFAULT_VERBOSITY,
    }

    @classmethod
    def add_args_to_parser(cls, parser: ArgumentParser):
        pass

    def __init__(
        self,
        console: Console,
        error_console: Console,
        progress: Progress,
        *,
        verbose: int | None = None,
    ):
        self.console: Console = console
        self.error_console: Console = error_console
        self.progress: Progress = progress

        self.verbose = verbose if not None else self.arg_defaults["verbose"]

        self.queue: ScapChunkQueue[T] | None = None
        self.task: TaskID | None = None
        self.processed: int = 0

    @abstractmethod
    async def add_chunk(self, chunk: Sequence[T]) -> None:
        pass

    async def loop_start(self) -> None:
        self.console.log(f"Start processing {self.item_type_plural}")
        self.task = self.progress.add_task(
            f"Processing {self.item_type_plural}", total=self.queue.total_items
        )

    async def loop_step_end(self) -> None:
        if self.verbose:
            self.console.log(
                f"Processed {self.processed:,} of {self.queue.total_items:,} "
                f"{self.item_type_plural}"
            )

    async def loop_end(self) -> None:
        self.console.log(
            f"Processing of {self.processed:,} {self.item_type_plural} done"
        )

    async def run_loop(self) -> None:

        await self.loop_start()
        while self.queue.more_chunks_expected():
            try:
                chunk = await self.queue.get_chunk()
                self.processed += len(chunk)

                if self.task is None:
                    raise ScapError("Worker progress task is not defined")

                self.progress.update(self.task, completed=self.processed)

                await self.add_chunk(chunk)
            except asyncio.CancelledError as e:
                if self.verbose:
                    self.console.log("Worker has been cancelled")
                raise e

            self.queue.task_done()

            await self.loop_step_end()

        await self.loop_end()

    def set_queue(self, queue: ScapChunkQueue[T]):
        self.queue = queue
