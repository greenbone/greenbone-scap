# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import ArgumentParser, Namespace
from typing import Sequence

import shtab
from rich.progress import Progress

from greenbone.scap.cli import CLIRunner
from greenbone.scap.cpe_match.cli.processor import CpeMatchProcessor

from ..producer.nvd_api import CpeMatchNvdApiProducer
from ..worker.json import CpeMatchJsonWriteWorker


def parse_args(args: Sequence[str] | None = None) -> Namespace:
    parser = ArgumentParser(
        description="Download and consolidate CPE match strings. "
        "Downloads CPE match string information from the NIST NVD REST API "
        "and consolidates it into a single JSON file."
    )
    shtab.add_argument_to(parser)

    CpeMatchNvdApiProducer.add_args_to_parser(parser)

    CpeMatchJsonWriteWorker.add_args_to_parser(parser)

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

        worker = CpeMatchJsonWriteWorker.from_args(
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
