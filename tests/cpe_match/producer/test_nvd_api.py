# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from pontos.testing import temp_file
from rich.console import Console
from rich.progress import Progress

from greenbone.scap.cli import DEFAULT_RETRIES, DEFAULT_VERBOSITY
from greenbone.scap.cpe_match.cli.processor import CpeMatchProcessor
from greenbone.scap.cpe_match.producer.nvd_api import CpeMatchNvdApiProducer


def parse_producer_args(raw_args):
    parser = argparse.ArgumentParser()
    CpeMatchProcessor.add_args_to_parser(
        parser
    )  # for common args like "verbose"
    CpeMatchNvdApiProducer.add_args_to_parser(parser)
    return parser.parse_args(raw_args)


class ParseArgsTestCase(unittest.TestCase):
    @patch(
        "greenbone.scap.cpe_match.producer.nvd_api.CpeMatchNvdApiProducer",
        autospec=True,
    )
    def test_defaults(self, mock_producer: MagicMock):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        args = parse_producer_args([])

        CpeMatchNvdApiProducer.from_args(args, console, error_console, progress)

        mock_producer.assert_called_once_with(
            console=console,
            error_console=error_console,
            progress=progress,
            nvd_api_key=None,
            retry_attempts=DEFAULT_RETRIES,
            request_results=None,
            request_filter_opts={},
            start_index=None,
            verbose=DEFAULT_VERBOSITY,
        )

    @patch(
        "greenbone.scap.cpe_match.producer.nvd_api.CpeMatchNvdApiProducer",
        autospec=True,
    )
    def test_since(self, mock_producer: MagicMock):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        args = parse_producer_args(
            [
                "--since",
                "2024-12-09",
            ]
        )

        CpeMatchNvdApiProducer.from_args(args, console, error_console, progress)

        mock_producer.assert_called_once_with(
            console=console,
            error_console=error_console,
            progress=progress,
            nvd_api_key=None,
            retry_attempts=DEFAULT_RETRIES,
            request_results=None,
            request_filter_opts={
                "last_modified_start_date": datetime(2024, 12, 9)
            },
            start_index=None,
            verbose=DEFAULT_VERBOSITY,
        )

    @patch(
        "greenbone.scap.cpe_match.producer.nvd_api.CpeMatchNvdApiProducer",
        autospec=True,
    )
    def test_since_from_file(self, mock_producer: MagicMock):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        with temp_file("2024-12-05\n", name="since.txt") as temp_file_path:
            args = parse_producer_args(
                [
                    "--since-from-file",
                    str(temp_file_path),
                ]
            )

            CpeMatchNvdApiProducer.from_args(
                args, console, error_console, progress
            )

            mock_producer.assert_called_once_with(
                console=console,
                error_console=error_console,
                progress=progress,
                nvd_api_key=None,
                retry_attempts=DEFAULT_RETRIES,
                request_results=None,
                request_filter_opts={
                    "last_modified_start_date": datetime(2024, 12, 5)
                },
                start_index=None,
                verbose=DEFAULT_VERBOSITY,
            )

    @patch(
        "greenbone.scap.cpe_match.producer.nvd_api.CpeMatchNvdApiProducer",
        autospec=True,
    )
    def test_since_number(self, mock_producer: MagicMock):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        args = parse_producer_args(
            [
                "--number",
                "123",
            ]
        )

        CpeMatchNvdApiProducer.from_args(args, console, error_console, progress)

        mock_producer.assert_called_once_with(
            console=console,
            error_console=error_console,
            progress=progress,
            nvd_api_key=None,
            retry_attempts=DEFAULT_RETRIES,
            request_results=123,
            request_filter_opts={},
            start_index=None,
            verbose=DEFAULT_VERBOSITY,
        )

    @patch(
        "greenbone.scap.cpe_match.producer.nvd_api.CpeMatchNvdApiProducer",
        autospec=True,
    )
    def test_number(self, mock_producer: MagicMock):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        args = parse_producer_args(
            [
                "--number",
                "123",
            ]
        )

        CpeMatchNvdApiProducer.from_args(args, console, error_console, progress)

        mock_producer.assert_called_once_with(
            console=console,
            error_console=error_console,
            progress=progress,
            nvd_api_key=None,
            retry_attempts=DEFAULT_RETRIES,
            request_results=123,
            request_filter_opts={},
            start_index=None,
            verbose=DEFAULT_VERBOSITY,
        )

    @patch(
        "greenbone.scap.cpe_match.producer.nvd_api.CpeMatchNvdApiProducer",
        autospec=True,
    )
    def test_start(self, mock_producer: MagicMock):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        args = parse_producer_args(
            [
                "--start",
                "321",
            ]
        )

        CpeMatchNvdApiProducer.from_args(args, console, error_console, progress)

        mock_producer.assert_called_once_with(
            console=console,
            error_console=error_console,
            progress=progress,
            nvd_api_key=None,
            retry_attempts=DEFAULT_RETRIES,
            request_results=None,
            request_filter_opts={},
            start_index=321,
            verbose=DEFAULT_VERBOSITY,
        )

    @patch(
        "greenbone.scap.cpe_match.producer.nvd_api.CpeMatchNvdApiProducer",
        autospec=True,
    )
    def test_retry_attempts(self, mock_producer: MagicMock):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        args = parse_producer_args(
            [
                "--retry-attempts",
                "7",
            ]
        )

        CpeMatchNvdApiProducer.from_args(args, console, error_console, progress)

        mock_producer.assert_called_once_with(
            console=console,
            error_console=error_console,
            progress=progress,
            nvd_api_key=None,
            retry_attempts=7,
            request_results=None,
            request_filter_opts={},
            start_index=None,
            verbose=DEFAULT_VERBOSITY,
        )

    @patch(
        "greenbone.scap.cpe_match.producer.nvd_api.CpeMatchNvdApiProducer",
        autospec=True,
    )
    def test_nvd_api_key(self, mock_producer: MagicMock):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        args = parse_producer_args(
            [
                "--nvd-api-key",
                "token123",
            ]
        )

        CpeMatchNvdApiProducer.from_args(args, console, error_console, progress)

        mock_producer.assert_called_once_with(
            console=console,
            error_console=error_console,
            progress=progress,
            nvd_api_key="token123",
            retry_attempts=DEFAULT_RETRIES,
            request_results=None,
            request_filter_opts={},
            start_index=None,
            verbose=DEFAULT_VERBOSITY,
        )
