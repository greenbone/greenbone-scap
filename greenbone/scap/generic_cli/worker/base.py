# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
from abc import ABC, abstractmethod
from argparse import ArgumentParser
from typing import Any, AsyncContextManager, Generic, Sequence, TypeVar

from rich.console import Console
from rich.progress import Progress, TaskID

from ...cli import DEFAULT_VERBOSITY
from ...errors import ScapError
from ..queue import ScapChunkQueue

T = TypeVar("T")
"Generic type variable for the type of SCAP items handled"


class BaseScapWorker(Generic[T], AsyncContextManager, ABC):
    """
    Abstract async context manager base class for a worker consuming
    SCAP items, e.g. by writing them to a file or database.

    The type of the SCAP items is to be specified by the generic type,
    e.g. `BaseScapWorker[CPE]` will be a producer handling CPE objects.
    """

    _item_type_plural: str = "SCAP items"
    "Plural form of the type of items to use in log messages."

    _arg_defaults: dict[str, Any] = {
        "verbose": DEFAULT_VERBOSITY,
    }
    "Default values for optional arguments."

    @classmethod
    def add_args_to_parser(cls, parser: ArgumentParser):
        """
        Class method for adding worker-specific arguments to an
        `ArgumentParser`. Does nothing but can be overridden by
        more specific producers.

        Args:
            parser: The parser to add the arguments to.
        """
        pass

    def __init__(
        self,
        console: Console,
        error_console: Console,
        progress: Progress,
        *,
        verbose: int | None = None,
    ):
        """
        Constructor for a generic SCAP worker.

        Args:
            console: Console for standard output.
            error_console: Console for error output.
            progress: Progress bar renderer to be updated by the producer.
            verbose: Verbosity level of log messages.
        """

        self._console: Console = console
        "Console for standard output."

        self._error_console: Console = error_console
        "Console for error output."

        self._progress: Progress = progress
        "Progress bar renderer to be updated by the producer."

        self._verbose = verbose if not None else self._arg_defaults["verbose"]
        "Verbosity level of log messages."

        self._queue: ScapChunkQueue[T]
        "Queue the worker will get chunks of SCAP items from."

        self._progress_task: TaskID | None = None
        "Progress bar TaskID tracking the progress of the worker."

        self._processed: int = 0
        "Number of SCAP items processed so far."

    @abstractmethod
    async def _handle_chunk(self, chunk: Sequence[T]) -> None:
        """
        Callback handling a chunk of SCAP items from the queue.

        Args:
            chunk: The last chunk fetched from the queue.
        """
        pass

    async def _loop_start(self) -> None:
        """
        Callback handling the start of the loop fetching and processing the SCAP items.
        """
        self._console.log(f"Start processing {self._item_type_plural}")
        self._progress_task = self._progress.add_task(
            f"Processing {self._item_type_plural}",
            total=self._queue.total_items,
        )

    async def _loop_step_end(self) -> None:
        """
        Callback handling the end of one iteration of the main worker loop.
        """
        if self._verbose:
            self._console.log(
                f"Processed {self._processed:,} of {self._queue.total_items:,} "
                f"{self._item_type_plural}"
            )

    async def _loop_end(self) -> None:
        """
        Callback handling the exiting the main worker loop.
        """
        self._console.log(
            f"Processing of {self._processed:,} {self._item_type_plural} done"
        )

    async def run_loop(self) -> None:
        """
        Runs the main loop of the worker while there are chunks expected by the queue.

        The function will fetch chunks from the queue and handle them in the `handle_chunk`
        callback.

        It will also call `loop_step_end` after each iteration of the loop and `loop_end`
        after exiting the loop.
        """
        if self._queue is None:
            raise ScapError("No queue has been assigned")

        await self._loop_start()
        while self._queue.more_chunks_expected():
            try:
                chunk = await self._queue.get_chunk()
                self._processed += len(chunk)

                if self._progress_task is None:
                    raise ScapError("Worker progress task is not defined")

                self._progress.update(
                    self._progress_task, completed=self._processed
                )

                await self._handle_chunk(chunk)
            except asyncio.CancelledError as e:
                if self._verbose:
                    self._console.log("Worker has been cancelled")
                raise e

            self._queue.chunk_processed()

            await self._loop_step_end()

        await self._loop_end()

    def set_queue(self, queue: ScapChunkQueue[T]) -> None:
        """
        Assigns a SCAP chunk queue to the worker.

        This will be called by the `ScapProcessor`, so the worker can be created
        before the processor that provides the queue.

        Args:
            queue: The queue to assign.
        """
        self._queue = queue
