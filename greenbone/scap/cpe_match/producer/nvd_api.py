# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later
from argparse import Namespace

from pontos.nvd import NVDApi, NVDResults
from pontos.nvd.cpe_match import CPEMatchApi
from pontos.nvd.models.cpe_match_string import CPEMatchString
from rich.console import Console
from rich.progress import Progress

from ...generic_cli.producer.nvd_api import NvdApiProducer
from ..cli.processor import CPE_MATCH_TYPE_PLURAL


class CpeMatchNvdApiProducer(NvdApiProducer[CPEMatchString]):
    item_type_plural = CPE_MATCH_TYPE_PLURAL
    arg_defaults = NvdApiProducer.arg_defaults

    @classmethod
    def from_args(
        cls,
        args: Namespace,
        console: Console,
        error_console: Console,
        progress: Progress,
    ) -> "CpeMatchNvdApiProducer":
        request_filter_opts = {}

        since = NvdApiProducer.since_from_args(args, error_console)
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
        nvd_api_key: str | None = None,
        retry_attempts: int = None,
        request_results: int = None,
        request_filter_opts: dict = {},
        start_index: int = 0,
        verbose: int = None,
    ):
        super().__init__(
            console,
            error_console,
            progress,
            nvd_api_key=nvd_api_key,
            retry_attempts=retry_attempts,
            request_results=request_results,
            request_filter_opts=request_filter_opts,
            start_index=start_index,
            verbose=verbose,
        )

    def _create_nvd_api(self, nvd_api_key: str) -> NVDApi:
        return CPEMatchApi(
            token=nvd_api_key,
        )

    async def _create_nvd_results(self) -> NVDResults[CPEMatchString]:
        return await self._nvd_api.cpe_matches(
            last_modified_start_date=self.request_filter_opts.get(
                "last_modified_start_date"
            ),
            last_modified_end_date=self.request_filter_opts.get(
                "last_modified_start_date"
            ),
            cve_id=self.request_filter_opts.get("cve_id"),
            match_string_search=self.request_filter_opts.get(
                "match_string_search"
            ),
            request_results=self.request_results,
            start_index=self.start_index,
            results_per_page=self.queue.chunk_size,
        )
