# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later
import asyncio
from argparse import ArgumentParser
from typing import Generic, TypeVar

from rich.console import Console

from ..cli import DEFAULT_VERBOSITY
from .producer.base import BaseScapProducer
from .queue import DEFAULT_CHUNK_SIZE, DEFAULT_QUEUE_SIZE, ScapChunkQueue
from .worker.base import BaseScapWorker

T = TypeVar("T")
"Generic type variable for the type of SCAP items handled"


class ScapProcessor(Generic[T]):
    """
    Generic class that handles a producer object generating SCAP items
    to be processed by a worker object.

    The type of the SCAP items is to be specified by the generic type,
    e.g. `ScapProcessor[CPE]` will be a processor handling CPE objects.
    """

    _item_type_plural = "SCAP items"
    "Plural form of the type of items to use in log messages."

    _arg_defaults = {
        "chunk_size": DEFAULT_CHUNK_SIZE,
        "queue_size": DEFAULT_QUEUE_SIZE,
        "verbose": DEFAULT_VERBOSITY,
    }
    "Default values for optional arguments."

    @classmethod
    def add_args_to_parser(
        cls,
        parser: ArgumentParser,
    ):
        """
        Adds arguments common to all SCAP processors to an `ArgumentParser`.

        Args:
            parser: The parser to add arguments to.
        """
        parser.add_argument(
            "--chunk-size",
            help=f"Number of {cls._item_type_plural} to download and process in one request. "
            "A lower number allows for more frequent updates and feedback. "
            "Default: %(default)s.",
            type=int,
            metavar="N",
            default=cls._arg_defaults["chunk_size"],
        )
        parser.add_argument(
            "--queue-size",
            help="Size of the download queue. It sets the maximum number of "
            f"{cls._item_type_plural} kept in the memory. "
            "The maximum number of CPEs is chunk size * queue size. "
            "Default: %(default)s.",
            type=int,
            metavar="N",
            default=cls._arg_defaults["queue_size"],
        )
        parser.add_argument(
            "-v",
            "--verbose",
            action="count",
            default=cls._arg_defaults["verbose"],
            help="Enable verbose output.",
        )

    def __init__(
        self,
        console: Console,
        error_console: Console,
        producer: BaseScapProducer[T],
        worker: BaseScapWorker[T],
        *,
        queue_size: int | None = None,
        chunk_size: int | None = None,
        verbose: int | None = None,
    ):
        """
        Constructor for a new SCAP processor.

        Args:
            console: Console for standard output.
            error_console: Console for error output.
            producer: The producer generating the SCAP items.
            worker: The worker processing the SCAP items.
            queue_size: The number of chunks allowed in the queue.
            chunk_size: The expected maximum number of SCAP items per chunk.
            verbose: Verbosity level of log messages.
        """

        self._console: Console = console
        "Console for standard output."

        self._error_console: Console = error_console
        "Console for error output."

        self._producer: BaseScapProducer[T] = producer
        "The producer generating the SCAP items."

        self._worker: BaseScapWorker[T] = worker
        "The worker processing the SCAP items."

        self._queue: ScapChunkQueue[T] = ScapChunkQueue[T](
            queue_size=queue_size or self._arg_defaults["queue_size"],
            chunk_size=chunk_size or self._arg_defaults["chunk_size"],
        )
        "Queue the producer will add chunks to and the worker get chunks from."
        self._producer.set_queue(self._queue)
        self._worker.set_queue(self._queue)

        self._verbose: int = (
            verbose if verbose is not None else self._arg_defaults["verbose"]
        )
        "Verbosity level of log messages."

    async def run(self) -> None:
        """
        Runs the main loops of the producer and worker objects as concurrent
        subroutines.

        This also handles the producer and worker as context managers and
        fetches initial data like the expected total number of items from the
        producer.

        The function will block until the producer finishes and the queue
        is empty and finished processing.
        """
        async with self._producer, self._worker:
            total_items = await self._producer.fetch_initial_data()
            if total_items <= 0:
                return
            self._queue.total_items = total_items

            async with asyncio.TaskGroup() as tg:
                producer_task = tg.create_task(self._producer.run_loop())
                tg.create_task(self._worker.run_loop())
                await producer_task
                await self._join()

    async def _join(self) -> None:
        """
        Blocks until all chunks in the queue are fetched and processed.
        """
        await self._queue.join()
