# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import os
from argparse import ArgumentParser, Namespace
from datetime import datetime
from pathlib import Path
from typing import Sequence

import shtab
import stamina
from pontos.nvd import now
from pontos.nvd.api import NVDResults
from pontos.nvd.cve import CVEApi
from pontos.nvd.models.cve import CVE
from rich.console import Console
from rich.progress import Progress

from greenbone.scap.cli import (
    DEFAULT_POSTGRES_DATABASE_NAME,
    DEFAULT_POSTGRES_HOST,
    DEFAULT_POSTGRES_PORT,
    DEFAULT_POSTGRES_USER,
    DEFAULT_RETRIES,
    DEFAULT_VERBOSITY,
    CLIError,
    CLIRunner,
)
from greenbone.scap.constants import STAMINA_API_RETRY_EXCEPTIONS
from greenbone.scap.cve.manager import CVEManager
from greenbone.scap.db import PostgresDatabase
from greenbone.scap.timer import Timer

# disable stamina logging
stamina.instrumentation.set_on_retry_hooks([])

DEFAULT_QUEUE_SIZE = 10


def parse_args(args: Sequence[str] | None = None) -> Namespace:
    parser = ArgumentParser(
        description="Create and update a CVE database. "
        "Downloads CVE information from the NIST NVD REST API into the database."
    )
    shtab.add_argument_to(parser)

    parser.add_argument(
        "--number",
        "-n",
        metavar="N",
        help="Download up to N CVEs only",
        type=int,
    )

    db_group = parser.add_argument_group(
        title="Database", description="Database related settings"
    )
    db_group.add_argument(
        "--database-name",
        help="Name of the CVE database.",
    )
    db_group.add_argument(
        "--database-host",
        help="Name of the CVE database host.",
    )
    db_group.add_argument(
        "--database-port",
        help="Name of the CVE database port.",
        type=int,
    )
    db_group.add_argument(
        "--database-user",
        help="Name of the CVE database user.",
    )
    db_group.add_argument(
        "--database-password",
        help="Name of the CVE database password.",
    )
    db_group.add_argument(
        "--database-schema",
        help="Name of the CVE database schema.",
    )

    since_group = parser.add_mutually_exclusive_group()
    since_group.add_argument(
        "--since",
        metavar="DATE",
        type=datetime.fromisoformat,
        help="Load all CVE changes since a specific date.",
    )
    since_group.add_argument(
        "--since-from-file",
        type=Path,
        metavar="FILE",
        help="Load all CVE changes since a specific date. The date is read "
        "from FILE.",
    )

    parser.add_argument(
        "--store-runtime",
        metavar="FILE",
        type=Path,
        help="Store time of this run in FILE. It can be used to load only the "
        "modified CVEs next time using the --since-from-time argument.",
    )
    parser.add_argument(
        "--store-updated-cves",
        metavar="FILE",
        type=Path,
        help="Store the list of updated CVEs in FILE. It can be used as "
        "input for the CVE convert tool to only convert updated CVEs.",
    )

    parser.add_argument(
        "--echo-sql",
        action="store_true",
        help="Print out all SQL queries.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        help="Enable verbose output.",
    )
    parser.add_argument(
        "--retry-attempts",
        type=int,
        metavar="N",
        help="Up to N retries until giving up when HTTP requests are failing. "
        f"Default: {DEFAULT_RETRIES}",
    )
    parser.add_argument(
        "--nvd-api-key",
        metavar="KEY",
        help="Use a NVD API key for downloading the CVEs. Using an API key "
        "allows for downloading with extended rate limits.",
    )
    parser.add_argument(
        "--chunk-size",
        help="Number of CVEs to download and process in one request. A lower "
        "number allows for more frequent updates and feedback.",
        type=int,
        metavar="N",
    )
    parser.add_argument(
        "--queue-size",
        help="Size of the download queue. It sets the maximum number of CVEs "
        "kept in the memory. The maximum number of CVEs is chunk size * queue "
        "size. Default: %(default)s.",
        type=int,
        metavar="N",
        default=DEFAULT_QUEUE_SIZE,
    )
    return parser.parse_args(args)


class CVECli:
    def __init__(
        self,
        console: Console,
        *,
        verbose: int = 0,
        chunk_size: int | None = None,
        queue_size: int = DEFAULT_QUEUE_SIZE,
    ) -> None:
        self.queue: asyncio.Queue[Sequence[CVE]] = asyncio.Queue(queue_size)
        self.chunk_size = chunk_size
        self.console = console
        self.event = asyncio.Event()
        self.verbose = verbose
        self.cves_to_update: set[str] = set()

    async def _worker(
        self, progress: Progress, manager: CVEManager, total_cves: int
    ):
        self.console.log("Start processing CVEs")
        processed = 0

        task = progress.add_task("Processing CVEs", total=total_cves)
        while not self.event.is_set() or not self.queue.empty():
            try:
                cves = await self.queue.get()

                await manager.add_cves(cves)

                self.cves_to_update.update((cve.id for cve in cves))

                self.queue.task_done()

                processed += len(cves)
                progress.update(task, completed=processed)

                self.console.log(f"Processed {processed:,} CVEs")
            except asyncio.CancelledError as e:
                self.console.log("Worker has been cancelled")
                raise e

        self.console.log(f"Processing of {processed:,} CVEs done")

    async def _producer(
        self,
        progress: Progress,
        results: NVDResults[CVE],
        retry_attempts: int,
        total_cves: int,
    ) -> None:
        task = progress.add_task("Downloading CVEs", total=total_cves)

        try:
            with Timer() as download_timer:
                count = 0
                async for attempt in stamina.retry_context(
                    on=STAMINA_API_RETRY_EXCEPTIONS,
                    attempts=retry_attempts,
                    timeout=None,
                ):
                    with attempt:
                        attempt_number = attempt.num
                        if attempt_number > 1:
                            self.console.log(
                                "HTTP request failed. Download attempt "
                                f"{attempt_number} of {retry_attempts}"
                            )

                        async for cves in results.chunks():
                            count += len(cves)
                            progress.update(task, completed=count)

                            if self.verbose:
                                self.console.log(f"Downloaded {count:,} CVEs")

                            await self.queue.put(cves)
        finally:
            # signal worker that we are finished with downloading
            self.event.set()

        self.console.log(
            f"Downloaded {count:,} CVEs in "
            f"{download_timer.elapsed_time:0.4f} seconds."
        )

    async def _join(self):
        await self.queue.join()

    async def download(
        self,
        progress: Progress,
        manager: CVEManager,
        api: CVEApi,
        retry_attempts: int,
        request_results: int | None,
        last_modified_start_date: datetime | None,
        last_modified_end_date: datetime | None,
    ) -> None:
        async for attempt in stamina.retry_context(
            on=STAMINA_API_RETRY_EXCEPTIONS,
            attempts=retry_attempts,
            timeout=None,
        ):
            with attempt:
                attempt_number = attempt.num
                additional_retry_attempts = retry_attempts - (
                    attempt_number - 1
                )
                if attempt_number > 1:
                    self.console.log(
                        "HTTP request failed. Download attempt "
                        f"{attempt_number} of {retry_attempts}"
                    )
                else:
                    self.console.log(
                        f"Download attempt {attempt_number} of {retry_attempts}"
                    )

                results = await api.cves(
                    request_results=request_results,
                    last_modified_start_date=last_modified_start_date,
                    last_modified_end_date=last_modified_end_date,
                    results_per_page=self.chunk_size,
                )

        result_count = len(results)  # type: ignore

        self.console.log(f"{result_count:,} CVEs to download available")

        if request_results == 0 or not result_count:
            # no new CVEs available or no CVEs requested
            return

        total_cves = min(request_results or result_count, result_count)

        async with asyncio.TaskGroup() as tg:
            tg.create_task(
                self._worker(
                    progress,
                    manager,
                    total_cves=total_cves,
                )
            )
            producer = tg.create_task(
                self._producer(
                    progress,
                    results,
                    additional_retry_attempts,
                    total_cves=total_cves,
                )
            )
            await producer
            await self._join()


async def download(console: Console, error_console: Console):
    args = parse_args()

    since: datetime | None = args.since
    verbose: int = (
        args.verbose
        if args.verbose is not None
        else int(os.environ.get("VERBOSE", DEFAULT_VERBOSITY))
    )
    run_time_file: Path | None = args.store_runtime
    since_from_file: Path | None = args.since_from_file
    echo_sql: bool = args.echo_sql
    number: int | None = args.number
    retry_attempts: int = args.retry_attempts or int(
        os.environ.get("RETRY_ATTEMPTS", DEFAULT_RETRIES)
    )
    nvd_api_key: str | None = args.nvd_api_key or os.environ.get("NVD_API_KEY")
    updated_cves_file: Path | None = args.store_updated_cves

    chunk_size: int | None = args.chunk_size
    queue_size: int = args.queue_size

    until = now() if run_time_file else None

    if since_from_file:
        if since_from_file.exists():
            since = datetime.fromisoformat(
                since_from_file.read_text(encoding="utf8").strip()
            )
        else:
            error_console.print(
                f"{since_from_file.absolute()} does not exist. Ignoring "
                "--since-from-file argument."
            )
            since = None

    cve_database_name = (
        args.database_name
        or os.environ.get("CVE_DATABASE_NAME")
        or os.environ.get("DATABASE_NAME")
        or DEFAULT_POSTGRES_DATABASE_NAME
    )
    cve_database_user: str = (
        args.database_user
        or os.environ.get("CVE_DATABASE_USER")
        or os.environ.get("DATABASE_USER")
        or DEFAULT_POSTGRES_USER
    )
    cve_database_host: str = (
        args.database_host
        or os.environ.get("CVE_DATABASE_HOST")
        or os.environ.get("DATABASE_HOST")
        or DEFAULT_POSTGRES_HOST
    )
    cve_database_port: int = int(
        args.database_port
        or os.environ.get("CVE_DATABASE_PORT")
        or os.environ.get("DATABASE_PORT")
        or DEFAULT_POSTGRES_PORT
    )
    cve_database_schema: str | None = (
        args.database_schema
        or os.environ.get("CVE_DATABASE_SCHEMA")
        or os.environ.get("DATABASE_SCHEMA")
    )
    cve_database_password: str | None = (
        args.database_password
        or os.environ.get("CVE_DATABASE_PASSWORD")
        or os.environ.get("DATABASE_PASSWORD")
    )
    if not cve_database_password:
        raise CLIError("Missing password for CVE database")

    cve_database = PostgresDatabase(
        user=cve_database_user,
        password=cve_database_password,
        host=cve_database_host,
        port=cve_database_port,
        dbname=cve_database_name,
        schema=cve_database_schema,
        echo=echo_sql,
    )
    if verbose:
        console.log(f"Using PostgreSQL database {cve_database_name} for CVEs")

    cli = CVECli(
        console, verbose=verbose, chunk_size=chunk_size, queue_size=queue_size
    )

    run_time = datetime.now()

    with Progress(console=console) as progress:
        async with (
            cve_database,
            CVEApi(token=nvd_api_key) as api,
            CVEManager(cve_database) as cve_manager,
        ):

            if verbose:
                console.log("Initialized databases.")

                if nvd_api_key:
                    console.log("Using NVD API key to download the CVEs")

            if number != 0:
                console.log("Start downloading CVEs")

                if since:
                    console.log(
                        "Downloading changed or new CVEs since "
                        f"{since.isoformat()}"
                    )

                await cli.download(
                    progress,
                    cve_manager,
                    api,
                    retry_attempts,
                    request_results=number,
                    last_modified_start_date=since,
                    last_modified_end_date=since and until,
                )

        if run_time_file:
            if until:
                run_time = until
            # ensure directories exist
            run_time_file.parent.mkdir(parents=True, exist_ok=True)
            run_time_file.write_text(
                f"{run_time.isoformat()}\n",
                encoding="utf8",  # type: ignore
            )
            console.log(f"Wrote run time to {run_time_file.absolute()}.")

        if updated_cves_file:
            # ensure directories exist
            updated_cves_file.parent.mkdir(parents=True, exist_ok=True)
            updated_cves_file.write_text(
                "\n".join(cli.cves_to_update), encoding="utf8"
            )
            console.log(
                f"Wrote {len(cli.cves_to_update):,} updated CVEs to "
                f"{updated_cves_file.absolute()}."
            )


def main() -> None:
    CLIRunner.run(download)


if __name__ == "__main__":
    main()
