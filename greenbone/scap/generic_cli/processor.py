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


class ScapProcessor(Generic[T]):
    item_type_plural = "SCAP items"
    arg_defaults = {
        "chunk_size": DEFAULT_CHUNK_SIZE,
        "queue_size": DEFAULT_QUEUE_SIZE,
        "verbose": DEFAULT_VERBOSITY,
    }

    @classmethod
    def add_args_to_parser(
        cls,
        parser: ArgumentParser,
    ):
        parser.add_argument(
            "--chunk-size",
            help=f"Number of {cls.item_type_plural} to download and process in one request. "
            "A lower number allows for more frequent updates and feedback. "
            "Default: %(default)s.",
            type=int,
            metavar="N",
            default=cls.arg_defaults["chunk_size"],
        )
        parser.add_argument(
            "--queue-size",
            help="Size of the download queue. It sets the maximum number of "
            f"{cls.item_type_plural} kept in the memory. "
            "The maximum number of CPEs is chunk size * queue size. "
            "Default: %(default)s.",
            type=int,
            metavar="N",
            default=cls.arg_defaults["chunk_size"],
        )
        parser.add_argument(
            "-v",
            "--verbose",
            action="count",
            default=cls.arg_defaults["verbose"],
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
        self.console = console
        self.error_console = error_console
        self.producer: BaseScapProducer[T] = producer
        self.worker: BaseScapWorker[T] = worker

        self.queue: ScapChunkQueue[T] = ScapChunkQueue[T](
            queue_size=queue_size or self.arg_defaults["queue_size"],
            chunk_size=chunk_size or self.arg_defaults["chunk_size"],
        )
        self.producer.set_queue(self.queue)
        self.worker.set_queue(self.queue)

        self.verbose = (verbose if not None else self.arg_defaults["verbose"],)

    async def run(self):
        async with self.producer, self.worker:
            total_items = await self.producer.fetch_initial_data()
            if total_items <= 0:
                return

            async with asyncio.TaskGroup() as tg:
                producer_task = tg.create_task(self.producer.run_loop())
                tg.create_task(self.worker.run_loop())
                await producer_task
                await self._join()

    async def _join(self):
        await self.queue.join()
