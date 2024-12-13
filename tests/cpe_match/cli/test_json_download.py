# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from datetime import datetime
from pathlib import Path

from greenbone.scap.cli import DEFAULT_RETRIES, DEFAULT_VERBOSITY
from greenbone.scap.cpe_match.cli.json_download import parse_args
from greenbone.scap.cpe_match.cli.processor import CPE_MATCH_DEFAULT_CHUNK_SIZE
from greenbone.scap.generic_cli.queue import DEFAULT_QUEUE_SIZE


class ParseArgsTestCase(unittest.TestCase):
    def test_defaults(self):
        args = parse_args([])

        self.assertIsNone(args.since)
        self.assertIsNone(args.since_from_file)
        self.assertIsNone(args.number)
        self.assertIsNone(args.start)
        self.assertEqual(DEFAULT_RETRIES, args.retry_attempts)
        self.assertIsNone(args.nvd_api_key)

        self.assertEqual(Path("."), args.storage_path)
        self.assertFalse(args.compress)

        self.assertEqual(CPE_MATCH_DEFAULT_CHUNK_SIZE, args.chunk_size)
        self.assertEqual(DEFAULT_QUEUE_SIZE, args.queue_size)
        self.assertEqual(DEFAULT_VERBOSITY, args.verbose)

    def test_since(self):
        args = parse_args(["--since", "2024-12-09"])
        self.assertEqual(datetime(2024, 12, 9), args.since)

    def test_since_from_file(self):
        args = parse_args(["--since-from-file", "/tmp/path"])
        self.assertEqual(Path("/tmp/path"), args.since_from_file)
