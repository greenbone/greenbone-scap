# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later
from abc import abstractmethod
from argparse import ArgumentParser, Namespace
from datetime import datetime
from pathlib import Path
from typing import Generic, TypeVar

import httpx
import stamina
from pontos.nvd import NVDApi, NVDResults
from rich.console import Console
from rich.progress import Progress

from greenbone.scap.cli import (
    DEFAULT_RETRIES,
    DEFAULT_VERBOSITY,
)

from ...timer import Timer
from .base import BaseScapProducer

T = TypeVar("T")


class NvdApiProducer(BaseScapProducer, Generic[T]):
    item_type_plural = BaseScapProducer.item_type_plural
    arg_defaults = {
        "retry_attempts": DEFAULT_RETRIES,
        "verbose": DEFAULT_VERBOSITY,
    }

    @classmethod
    def add_args_to_parser(
        cls,
        parser: ArgumentParser,
    ):
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
            help=f"Fetch up to N {cls.item_type_plural} only",
            type=int,
        )
        parser.add_argument(
            "--start",
            "-s",
            metavar="N",
            help=f"Start at index in the list of {cls.item_type_plural}",
            type=int,
        )
        parser.add_argument(
            "--retry-attempts",
            type=int,
            metavar="N",
            help="Up to N retries until giving up when HTTP requests are failing. "
            "Default: %(default)s",
            default=cls.arg_defaults["retry_attempts"],
        )
        parser.add_argument(
            "--nvd-api-key",
            metavar="KEY",
            help=f"Use a NVD API key for downloading the {cls.item_type_plural}. "
            "Using an API key allows for downloading with extended rate limits.",
        )

    @staticmethod
    def since_from_args(args: Namespace, error_console: Console) -> datetime:
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
        retry_attempts: int,
        nvd_api_key: str | None = None,
        request_results: int | None = None,
        request_filter_opts: dict = {},
        start_index: int = 0,
        verbose: int | None = None,
    ):
        super().__init__(
            console,
            error_console,
            progress,
            verbose=verbose,
        )

        self.retry_attempts: int = retry_attempts
        self.additional_retry_attempts: int = retry_attempts
        self.request_results: int = request_results
        self.request_filter_opts: dict = request_filter_opts
        self.start_index: int = start_index

        self._nvd_api_key = nvd_api_key
        self._nvd_api = self._create_nvd_api(nvd_api_key)

    @abstractmethod
    def _create_nvd_api(self, nvd_api_key: str) -> NVDApi:
        pass

    @abstractmethod
    def _create_nvd_results(self) -> NVDResults[T]:
        pass

    async def fetch_initial_data(
        self,
    ) -> int:
        """
        :return: The number of items returned by the initial request
        """
        async for attempt in stamina.retry_context(
            on=httpx.HTTPError,
            attempts=self.retry_attempts,
            timeout=None,
        ):
            with attempt:
                attempt_number = attempt.num
                self.additional_retry_attempts = self.retry_attempts - (
                    attempt_number - 1
                )
                if attempt_number > 1:
                    self.console.log(
                        "HTTP request failed. Download attempt "
                        f"{attempt_number} of {self.retry_attempts}"
                    )
                else:
                    self.console.log(
                        f"Download attempt {attempt_number} of {self.retry_attempts}"
                    )

                self.results = await self._create_nvd_results()

        result_count = len(self.results)  # type: ignore

        self.console.log(
            f"{result_count:,} {self.item_type_plural} to download available"
        )

        if self.request_results == 0 or not result_count:
            # no new CPE match strings available or no CPE match strings requested
            return 0

        total_items = min(self.request_results or result_count, result_count)

        self.queue.total_items = total_items
        return total_items

    async def run_loop(
        self,
    ) -> None:
        task = self.progress.add_task(
            f"Downloading {self.item_type_plural}", total=self.queue.total_items
        )

        try:
            with Timer() as download_timer:
                count = 0
                async for attempt in stamina.retry_context(
                    on=httpx.HTTPError,
                    attempts=self.additional_retry_attempts,
                    timeout=None,
                ):
                    with attempt:
                        attempt_number = attempt.num
                        if attempt_number > 1:
                            self.console.log(
                                "HTTP request failed. Download attempt "
                                f"{attempt_number} of {self.retry_attempts}"
                            )

                        async for chunk in self.results.chunks():
                            count += len(chunk)
                            self.progress.update(task, completed=count)

                            if self.verbose:
                                self.console.log(
                                    f"Downloaded {count:,} of {self.queue.total_items:,} {self.item_type_plural}"
                                )

                            await self.queue.put_chunk(chunk)

            self.console.log(
                f"Downloaded {count:,} {self.item_type_plural} in "
                f"{download_timer.elapsed_time:0.4f} seconds."
            )

        finally:
            # signal worker that we are finished with downloading
            self.queue.set_producer_finished()

    async def __aenter__(self):
        await self._nvd_api.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._nvd_api.__aexit__(exc_type, exc_val, exc_tb)
