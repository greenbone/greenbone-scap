# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from abc import ABC, abstractmethod
from argparse import ArgumentParser

from pontos.nvd import NVDResults
from typing import Generic, TypeVar, AsyncContextManager

from rich.console import Console
from rich.progress import Progress

from greenbone.scap.cli import (
    DEFAULT_VERBOSITY,
)

from ..queue import (
    ScapChunkQueue,
)

T = TypeVar("T")


class BaseScapProducer(Generic[T], AsyncContextManager, ABC):

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
        self.results: NVDResults[T] | None = None

    @abstractmethod
    async def fetch_initial_data(
        self,
    ) -> int:
        """
        Abstract method that must set the `expected_total` in the queue
        and ensure any remaining initializations of the data source are done,
        so it can be queried for chunks of SCAP items by `fetch_loop`.
        :return:
        """
        return 0

    @abstractmethod
    async def run_loop(
        self,
    ) -> None:
        """
        Abstract method that should fetch chunks of SCAP items and add them
        to the queue.

        It must also call `set_producer_finished` before returning to signal
        that no more chunks will be added to the queue.

        It should also create a task for the `progress` object and update it
        regularly.
        """
        self.queue.set_producer_finished()

    def set_queue(self, queue: ScapChunkQueue[T]):
        self.queue = queue
