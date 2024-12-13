# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import asyncio
import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from pontos.testing import temp_directory
from rich.console import Console
from rich.progress import Progress

from greenbone.scap.cli import DEFAULT_VERBOSITY
from greenbone.scap.cpe_match.cli.processor import CpeMatchProcessor
from greenbone.scap.cpe_match.worker.json import CpeMatchJsonWriteWorker
from tests.cpe_match.worker.mock_producer import CpeMatchMockProducer


def parse_worker_args(raw_args):
    parser = argparse.ArgumentParser()
    CpeMatchProcessor.add_args_to_parser(
        parser
    )  # for common args like "verbose"

    CpeMatchJsonWriteWorker.add_args_to_parser(parser)
    return parser.parse_args(raw_args)


class ParseArgsTestCase(unittest.TestCase):
    @patch(
        "greenbone.scap.cpe_match.worker.json.CpeMatchJsonWriteWorker",
        autospec=True,
    )
    def test_defaults(self, mock_worker: MagicMock):
        console = Console()
        error_console = Console()
        progress = Progress()

        args = parse_worker_args([])
        CpeMatchJsonWriteWorker.from_args(
            args, console, error_console, progress
        )

        mock_worker.assert_called_once_with(
            console=console,
            error_console=error_console,
            progress=progress,
            storage_path=Path("."),
            schema_path=None,
            compress=False,
            verbose=DEFAULT_VERBOSITY,
        )

    @patch(
        "greenbone.scap.cpe_match.worker.json.CpeMatchJsonWriteWorker",
        autospec=True,
    )
    def test_storage_path(self, mock_worker: MagicMock):
        console = Console()
        error_console = Console()
        progress = Progress()

        args = parse_worker_args(["--storage-path", "/tmp/test"])
        CpeMatchJsonWriteWorker.from_args(
            args, console, error_console, progress
        )

        mock_worker.assert_called_once_with(
            console=console,
            error_console=error_console,
            progress=progress,
            storage_path=Path("/tmp/test"),
            schema_path=None,
            compress=False,
            verbose=DEFAULT_VERBOSITY,
        )

    @patch(
        "greenbone.scap.cpe_match.worker.json.CpeMatchJsonWriteWorker",
        autospec=True,
    )
    def test_schema_path(self, mock_worker: MagicMock):
        console = Console()
        error_console = Console()
        progress = Progress()

        args = parse_worker_args(["--schema-path", "/tmp/test"])
        CpeMatchJsonWriteWorker.from_args(
            args, console, error_console, progress
        )

        mock_worker.assert_called_once_with(
            console=console,
            error_console=error_console,
            progress=progress,
            storage_path=Path("."),
            schema_path=Path("/tmp/test"),
            compress=False,
            verbose=DEFAULT_VERBOSITY,
        )

    @patch(
        "greenbone.scap.cpe_match.worker.json.CpeMatchJsonWriteWorker",
        autospec=True,
    )
    def test_compress(self, mock_worker: MagicMock):
        console = Console()
        error_console = Console()
        progress = Progress()

        args = parse_worker_args(["--compress"])
        CpeMatchJsonWriteWorker.from_args(
            args, console, error_console, progress
        )

        mock_worker.assert_called_once_with(
            console=console,
            error_console=error_console,
            progress=progress,
            storage_path=Path("."),
            schema_path=None,
            compress=True,
            verbose=DEFAULT_VERBOSITY,
        )


class WriteTestCase(unittest.IsolatedAsyncioTestCase):
    NUM_CHUNKS = 5
    CHUNK_SIZE = 3
    QUEUE_SIZE = 2

    async def test_write_json(self):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        with temp_directory() as temp_storage_path:
            producer = CpeMatchMockProducer(
                console=console,
                error_console=error_console,
                progress=progress,
                num_chunks=self.NUM_CHUNKS,
                chunk_size=self.CHUNK_SIZE,
            )
            worker = CpeMatchJsonWriteWorker(
                console=console,
                error_console=error_console,
                progress=progress,
                storage_path=temp_storage_path,
            )
            processor = CpeMatchProcessor(
                console,
                error_console,
                producer,
                worker,
                queue_size=self.QUEUE_SIZE,
                chunk_size=self.CHUNK_SIZE,
            )
            async with asyncio.timeout(10):
                await processor.run()

            temp_file_path: Path = temp_storage_path / "nvd-cpe-matches.json"
            self.assertTrue(temp_file_path.exists())
            with open(temp_file_path) as fp:
                parsed_json = json.load(fp)
            self.assertEqual(parsed_json.get("resultsPerPage"), 15)
            self.assertEqual(parsed_json.get("totalResults"), 15)
            self.assertIsNotNone(parsed_json.get("timestamp"))
            self.assertNotEqual("", parsed_json.get("timestamp"))

            match_strings = parsed_json.get("matchStrings")
            self.assertEqual(
                self.CHUNK_SIZE * self.NUM_CHUNKS, len(match_strings)
            )
            for match_string_item in match_strings:
                match_string = match_string_item.get("matchString")
                self.assertIsNotNone(match_string)
                self.assertIn("matchCriteriaId", match_string)
                self.assertIn("criteria", match_string)
                self.assertIn("created", match_string)
                self.assertIn("lastModified", match_string)
                self.assertIn("cpeLastModified", match_string)

    async def test_write_json_minimal(self):
        console = Console(quiet=True)
        error_console = Console(quiet=True)
        progress = Progress(disable=True)

        with temp_directory() as temp_storage_path:
            producer = CpeMatchMockProducer(
                console=console,
                error_console=error_console,
                progress=progress,
                num_chunks=self.NUM_CHUNKS,
                chunk_size=self.CHUNK_SIZE,
                minimal_cpe_match_strings=True,
            )
            worker = CpeMatchJsonWriteWorker(
                console=console,
                error_console=error_console,
                progress=progress,
                storage_path=temp_storage_path,
            )
            processor = CpeMatchProcessor(
                console,
                error_console,
                producer,
                worker,
                queue_size=self.QUEUE_SIZE,
                chunk_size=self.CHUNK_SIZE,
            )
            async with asyncio.timeout(10):
                await processor.run()

            temp_file_path: Path = temp_storage_path / "nvd-cpe-matches.json"
            self.assertTrue(temp_file_path.exists())
            with open(temp_file_path) as fp:
                parsed_json = json.load(fp)
            self.assertEqual(parsed_json.get("resultsPerPage"), 15)
            self.assertEqual(parsed_json.get("totalResults"), 15)
            self.assertIsNotNone(parsed_json.get("timestamp"))
            self.assertNotEqual("", parsed_json.get("timestamp"))

            match_strings = parsed_json.get("matchStrings")
            self.assertEqual(
                self.CHUNK_SIZE * self.NUM_CHUNKS, len(match_strings)
            )
            for match_string_item in match_strings:
                match_string = match_string_item.get("matchString")
                self.assertIsNotNone(match_string)
                self.assertIn("matchCriteriaId", match_string)
                self.assertIn("criteria", match_string)
                self.assertIn("created", match_string)
                self.assertIn("lastModified", match_string)
                self.assertNotIn("cpeLastModified", match_string)
