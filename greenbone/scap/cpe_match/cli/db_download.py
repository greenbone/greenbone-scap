# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import ArgumentParser, Namespace
from typing import Sequence

import shtab
from rich.progress import Progress

from ...cli import CLIRunner
from ...cpe_match.cli.processor import CpeMatchProcessor
from ..producer.nvd_api import CpeMatchNvdApiProducer
from ..worker.db import CpeMatchDatabaseWriteWorker


def parse_args(args: Sequence[str] | None = None) -> Namespace:
    parser = ArgumentParser(
        description="Update a CPE match strings database from an API. "
        "Downloads CPE match string information from the NIST NVD REST API "
        "and stores it in a database."
    )
    shtab.add_argument_to(parser)

    CpeMatchNvdApiProducer.add_args_to_parser(parser)

    CpeMatchDatabaseWriteWorker.add_args_to_parser(parser)

    CpeMatchProcessor.add_args_to_parser(parser)

    return parser.parse_args(args)


async def download(console, error_console) -> None:
    args = parse_args()

    with Progress(console=console) as progress:
        producer = CpeMatchNvdApiProducer.from_args(
            args,
            console,
            error_console,
            progress,
        )

        worker = CpeMatchDatabaseWriteWorker.from_args(
            args,
            console,
            error_console,
            progress,
        )

        processor = CpeMatchProcessor.from_args(
            args,
            console,
            error_console,
            producer,
            worker,
        )

        await processor.run()


def main() -> None:
    CLIRunner.run(download)


if __name__ == "__main__":
    main()
