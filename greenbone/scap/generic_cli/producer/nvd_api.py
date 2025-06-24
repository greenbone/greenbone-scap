# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later
from abc import abstractmethod
from argparse import ArgumentParser, Namespace
from datetime import datetime
from pathlib import Path
from typing import Any, Generic, TypeVar

import stamina
from pontos.nvd import NVDApi, NVDResults
from rich.console import Console
from rich.progress import Progress

from greenbone.scap.cli import (
    DEFAULT_RETRIES,
    DEFAULT_VERBOSITY,
)

from ...constants import STAMINA_API_RETRY_EXCEPTIONS
from ...timer import Timer
from .base import BaseScapProducer

T = TypeVar("T")
"Generic type variable for the type of SCAP items handled"


class NvdApiProducer(BaseScapProducer, Generic[T]):
    """
    Abstract async context manager base class for a producer querying
    SCAP items from an NVD API.

    The type of items is to be defined by the generic type T in subclasses.
    """

    _item_type_plural = BaseScapProducer._item_type_plural
    "Plural form of the type of items to use in log messages"

    _arg_defaults = {
        "retry_attempts": DEFAULT_RETRIES,
        "verbose": DEFAULT_VERBOSITY,
    }
    "Default values for optional arguments."

    @classmethod
    def add_args_to_parser(
        cls,
        parser: ArgumentParser,
    ):
        """
        Adds arguments for an NVD API producer to an `ArgumentParser`.

        Args:
            parser: The parser to add the arguments to.
        """
        since_group = parser.add_mutually_exclusive_group()
        since_group.add_argument(
            "--since",
            metavar="DATE",
            type=datetime.fromisoformat,
            help="Load all changes since a specific date",
        )
        since_group.add_argument(
            "--since-from-file",
            type=Path,
            metavar="FILE",
            help="Load all changes since a specific date. The date is read from "
            "FILE.",
        )

        parser.add_argument(
            "--number",
            "-n",
            metavar="N",
            help=f"Fetch up to N {cls._item_type_plural} only",
            type=int,
        )
        parser.add_argument(
            "--start",
            "-s",
            metavar="N",
            help=f"Start at index in the list of {cls._item_type_plural}",
            type=int,
        )
        parser.add_argument(
            "--retry-attempts",
            type=int,
            metavar="N",
            help="Up to N retries until giving up when HTTP requests are failing. "
            "Default: %(default)s",
            default=cls._arg_defaults["retry_attempts"],
        )
        parser.add_argument(
            "--nvd-api-key",
            metavar="KEY",
            help=f"Use a NVD API key for downloading the {cls._item_type_plural}. "
            "Using an API key allows for downloading with extended rate limits.",
        )

    @staticmethod
    def since_from_args(
        args: Namespace, error_console: Console
    ) -> datetime | None:
        """
        Gets the lower limit for the modification time from the given
         command line arguments, reading the time from a file if the
         argument `--since` is missing and `--since-from-file` was given.

        Args:
            args: Command line arguments collected by a `ArgumentParser`.
            error_console: Console for error messages.

        Returns:
            The requested minimum modification time.
        """
        if args.since:
            return args.since
        elif args.since_from_file:
            since_from_file = args.since_from_file
            if since_from_file.exists():
                return datetime.fromisoformat(
                    since_from_file.read_text(encoding="utf8").strip()
                )
            else:
                error_console.print(
                    f"{since_from_file.absolute()} does not exist. Ignoring "
                    "--since-from-file argument."
                )

        return None

    def __init__(
        self,
        console: Console,
        error_console: Console,
        progress: Progress,
        *,
        retry_attempts: int = DEFAULT_RETRIES,
        nvd_api_key: str | None = None,
        request_results: int | None = None,
        request_filter_opts: dict = {},
        start_index: int = 0,
        verbose: int | None = None,
    ):
        """
        Constructor for a generic NVD API producer.

        Args:
            console: Console for standard output.
            error_console: Console for error output.
            progress: Progress bar renderer to be updated by the producer.
            nvd_api_key: API key to use for the requests to allow faster requests.
            retry_attempts: Number of retries for downloading items.
            request_results: Maximum number of results to request from the API.
            request_filter_opts: Filter options to pass to the API requests.
            start_index: index/offset of the first item to request.
            verbose: Verbosity level of log messages.
        """
        super().__init__(
            console,
            error_console,
            progress,
            verbose=verbose,
        )

        self._retry_attempts: int = retry_attempts
        "Number of retries for downloading items."

        self._additional_retry_attempts: int = retry_attempts
        "Number of retries after fetching initial data."

        self._request_results: int | None = request_results
        "Maximum number of results to request from the API."

        self._request_filter_opts: dict[str, Any] = request_filter_opts
        "Filter options to pass to the API requests."

        self._start_index: int = start_index
        "Index/offset of the first item to request."

        self._nvd_api_key: str | None = nvd_api_key
        "API key to use for the requests to allow faster requests."

        self._nvd_api: NVDApi = self._create_nvd_api(nvd_api_key)
        "The NVD API object used for querying SCAP items."

        self._results: NVDResults[T]
        "The NVD results object created by the API to get the SCAP items from."

    @abstractmethod
    def _create_nvd_api(self, nvd_api_key: str | None) -> NVDApi:
        """
        Callback used by the constructor to create the
         NVD API object that can be queried for SCAP items.

        Args:
            nvd_api_key: An optional API key to allow faster requests.

        Returns: The new `NVDApi` object.
        """
        pass

    @abstractmethod
    async def _create_nvd_results(self) -> NVDResults[T]:
        """
        Callback used during `fetch_initial_data` to get
         the `NVDResults` object the SCAP items will be fetched from.

        Returns: The new `NVDResults` object.
        """
        pass

    async def fetch_initial_data(
        self,
    ) -> int:
        """
        Does the initial data request that will determine the number of
        SCAP items available for download. The expected number of items
        will be this or `_request_results`, whichever is less.

        Returns:
            The number of expected items.
        """
        async for attempt in stamina.retry_context(
            on=STAMINA_API_RETRY_EXCEPTIONS,
            attempts=self._retry_attempts,
            timeout=None,
        ):
            with attempt:
                attempt_number = attempt.num
                self._additional_retry_attempts = self._retry_attempts - (
                    attempt_number - 1
                )
                if attempt_number > 1:
                    self._console.log(
                        "HTTP request failed. Download attempt "
                        f"{attempt_number} of {self._retry_attempts}"
                    )
                else:
                    self._console.log(
                        f"Download attempt {attempt_number} of {self._retry_attempts}"
                    )

                self._results = await self._create_nvd_results()

        result_count = len(self._results)  # type: ignore

        self._console.log(
            f"{result_count:,} {self._item_type_plural} to download available"
        )

        if self._request_results == 0 or not result_count:
            # no new CPE match strings available or no CPE match strings requested
            return 0

        total_items = min(self._request_results or result_count, result_count)
        return total_items

    async def run_loop(
        self,
    ) -> None:
        """
        Fetches chunks of SCAP items and adds them to the queue.

        This can be reused for different types of SCAP items as the type-specific
        initializations are done by the abstract methods that need to be overridden
        accordingly.
        """
        task = self._progress.add_task(
            f"Downloading {self._item_type_plural}",
            total=self._queue.total_items,
        )

        try:
            with Timer() as download_timer:
                count = 0
                async for attempt in stamina.retry_context(
                    on=STAMINA_API_RETRY_EXCEPTIONS,
                    attempts=self._additional_retry_attempts,
                    timeout=None,
                ):
                    with attempt:
                        attempt_number = attempt.num
                        if attempt_number > 1:
                            self._console.log(
                                "HTTP request failed. Download attempt "
                                f"{attempt_number} of {self._retry_attempts}"
                            )

                        async for chunk in self._results.chunks():
                            count += len(chunk)
                            self._progress.update(task, completed=count)

                            if self._verbose:
                                self._console.log(
                                    f"Downloaded {count:,} of {self._queue.total_items:,} {self._item_type_plural}"
                                )

                            await self._queue.put_chunk(chunk)

            self._console.log(
                f"Downloaded {count:,} {self._item_type_plural} in "
                f"{download_timer.elapsed_time:0.4f} seconds."
            )

        finally:
            # signal worker that we are finished with downloading
            self._queue.set_producer_finished()

    async def __aenter__(self):
        """
        Callback for entering an async runtime context that will enter the context
        for the API.
        """
        await self._nvd_api.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None | bool:
        """
        Callback for exiting an async runtime context that will enter the context
        for the API.

        Args:
            exc_type: Exception type
            exc_val: Exception value
            exc_tb: Exception traceback
        """
        return await self._nvd_api.__aexit__(exc_type, exc_val, exc_tb)
