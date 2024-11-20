# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from abc import ABC, abstractmethod
from argparse import ArgumentParser
from typing import Any, AsyncContextManager, Generic, TypeVar

from rich.console import Console
from rich.progress import Progress

from greenbone.scap.cli import (
    DEFAULT_VERBOSITY,
)

from ..queue import (
    ScapChunkQueue,
)

T = TypeVar("T")
"Generic type variable for the type of SCAP items handled"


class BaseScapProducer(Generic[T], AsyncContextManager, ABC):
    """
    Abstract async context manager base class for a producer generating
    SCAP items, e.g. by downloading from an API or querying a database.

    The type of the SCAP items is to be specified by the generic type,
    e.g. `BaseScapProducer[CPE]` will be a producer handling CPE objects.
    """

    _item_type_plural: str = "SCAP items"
    "Plural form of the type of items to use in log messages"

    _arg_defaults: dict[str, Any] = {
        "verbose": DEFAULT_VERBOSITY,
    }
    "Default values for optional arguments."

    @classmethod
    def add_args_to_parser(cls, parser: ArgumentParser) -> None:
        """
        Adds producer-specific arguments to an `ArgumentParser`.
         Does nothing but can be overridden by more specific producers.

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
        Constructor for a generic SCAP producer.

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
        "Queue chunks of SCAP items are added to."

    @abstractmethod
    async def fetch_initial_data(
        self,
    ) -> int:
        """
        Ensures any remaining initializations of the data source are done,
         so it can be queried for chunks of SCAP items by `run_loop`.
        It must also return the expected total number of items that will be
         fetched.

        Returns:
            The expected total number of items.
        """
        return 0

    @abstractmethod
    async def run_loop(
        self,
    ) -> None:
        """
        Run a loop fetching chunks of SCAP items and adding them to the queue.

        The method must also call `set_producer_finished` before returning to signal
        that no more chunks will be added to the queue.

        It should also create a task for the `progress` object and update it
        regularly.
        """
        pass

    def set_queue(self, queue: ScapChunkQueue[T]) -> None:
        """
        Assigns a SCAP chunk queue to the producer.

        This will be called by the `ScapProcessor`, so the producer can be created
        before the processor that provides the queue.

        Args:
            queue: The queue to assign.
        """
        self._queue = queue
