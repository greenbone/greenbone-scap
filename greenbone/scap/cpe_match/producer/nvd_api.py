# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later
from argparse import Namespace

from pontos.nvd import NVDResults
from pontos.nvd.cpe_match import CPEMatchApi
from pontos.nvd.models.cpe_match_string import CPEMatchString
from rich.console import Console
from rich.progress import Progress

from greenbone.scap.cli import DEFAULT_RETRIES
from greenbone.scap.cpe_match.cli.processor import CPE_MATCH_TYPE_PLURAL
from greenbone.scap.errors import ScapError
from greenbone.scap.generic_cli.producer.nvd_api import NvdApiProducer


class CpeMatchNvdApiProducer(NvdApiProducer[CPEMatchString]):
    """
    Async context manager class for a producer querying
    CPE match strings from an NVD API.
    """

    _item_type_plural = CPE_MATCH_TYPE_PLURAL
    "Plural form of the type of items to use in log messages"

    _arg_defaults = NvdApiProducer._arg_defaults
    "Default values for optional arguments."

    @classmethod
    def from_args(
        cls,
        args: Namespace,
        console: Console,
        error_console: Console,
        progress: Progress,
    ) -> "CpeMatchNvdApiProducer":
        """
        Create a new `CPEMatchNvdApiProducer` with parameters from
         the given command line args gathered by an `ArgumentParser`.

        Args:
            args: Command line arguments to use
            console: Console for standard output.
            error_console: Console for error output.
            progress: Progress bar renderer to be updated by the producer.

        Returns:
            The new `CPEMatchNvdApiProducer`.
        """
        request_filter_opts = {}

        since = NvdApiProducer.since_from_args(args, error_console)
        if since is not None:
            request_filter_opts["last_modified_start_date"] = since

        return CpeMatchNvdApiProducer(
            console,
            error_console,
            progress,
            nvd_api_key=args.nvd_api_key,
            retry_attempts=args.retry_attempts,
            request_results=args.number,
            request_filter_opts=request_filter_opts,
            start_index=args.start,
            verbose=args.verbose or 0,
        )

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
        Constructor for a CPE match string NVD API producer.

        Args:
            console: Console for standard output.
            error_console: Console for error output.
            progress: Progress bar renderer to be updated by the producer.
            retry_attempts: Number of retries for downloading items
            nvd_api_key: API key to use for the requests to allow faster requests
            request_results: Total number of results to request from the API
            request_filter_opts: Filter options to pass to the API requests
            start_index: index/offset of the first item to request
            verbose: Verbosity level of log messages.
        """
        self._nvd_api: CPEMatchApi

        super().__init__(
            console,
            error_console,
            progress,
            retry_attempts=retry_attempts,
            nvd_api_key=nvd_api_key,
            request_results=request_results,
            request_filter_opts=request_filter_opts,
            start_index=start_index,
            verbose=verbose,
        )

    def _create_nvd_api(self, nvd_api_key: str | None) -> CPEMatchApi:
        """
        Callback used by the constructor to create the NVD API object
        that can be queried for CPE match strings.

        Args:
            nvd_api_key: An optional API key to allow faster requests.

        Returns: The new `CPEMatchApi` object, which inherits from `NVDApi`.
        """
        return CPEMatchApi(
            token=nvd_api_key,
        )

    async def _create_nvd_results(self) -> NVDResults[CPEMatchString]:
        """
        Callback used during `fetch_initial_data` getting
        the `NVDResults` object the CPE match strings will be fetched from.

        Returns: The new `NVDResults` object.
        """
        if self._queue is None:
            raise ScapError("No queue has been assigned")

        return await self._nvd_api.cpe_matches(
            last_modified_start_date=self._request_filter_opts.get(
                "last_modified_start_date"
            ),
            last_modified_end_date=self._request_filter_opts.get(
                "last_modified_end_date"
            ),
            cve_id=self._request_filter_opts.get("cve_id"),
            match_string_search=self._request_filter_opts.get(
                "match_string_search"
            ),
            request_results=self._request_results,
            start_index=self._start_index,
            results_per_page=self._queue.chunk_size,
        )
