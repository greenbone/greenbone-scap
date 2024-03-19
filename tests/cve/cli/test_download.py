# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from contextlib import redirect_stderr
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

from pontos.testing import temp_directory

from greenbone.scap.cve.cli.download import parse_args


class ParseArgsTestCase(unittest.TestCase):
    def test_defaults(self):
        args = parse_args([])

        self.assertIsNone(args.cve_database_name)
        self.assertIsNone(args.cve_database_host)
        self.assertIsNone(args.cve_database_port)
        self.assertIsNone(args.cve_database_user)
        self.assertIsNone(args.cve_database_password)
        self.assertIsNone(args.cve_database_schema)
        self.assertFalse(args.echo_sql)
        self.assertIsNone(args.verbose)
        self.assertIsNone(args.number)
        self.assertIsNone(args.retry_attempts)
        self.assertIsNone(args.nvd_api_key)
        self.assertIsNone(args.since)
        self.assertIsNone(args.since_from_file)
        self.assertIsNone(args.store_runtime)
        self.assertIsNone(args.store_updated_cves)

    def test_cve_database(self):
        args = parse_args(
            [
                "--cve-database-name",
                "scap",
                "--cve-database-host",
                "a-db-server",
                "--cve-database-port",
                "123",
                "--cve-database-user",
                "scap-user",
                "--cve-database-password",
                "1234",
                "--cve-database-schema",
                "scap-schema",
            ]
        )

        self.assertEqual(args.cve_database_name, "scap")
        self.assertEqual(args.cve_database_host, "a-db-server")
        self.assertEqual(args.cve_database_port, 123)
        self.assertEqual(args.cve_database_user, "scap-user")
        self.assertEqual(args.cve_database_password, "1234")
        self.assertEqual(args.cve_database_schema, "scap-schema")

    def test_echo_sql(self):
        args = parse_args(["--echo-sql"])

        self.assertTrue(args.echo_sql)

    def test_verbose(self):
        args = parse_args(["-v"])

        self.assertTrue(args.verbose, 1)

        args = parse_args(["-vv"])

        self.assertTrue(args.verbose, 2)

        args = parse_args(["-vvv"])

        self.assertTrue(args.verbose, 3)

        args = parse_args(["--verbose"])

        self.assertTrue(args.verbose, 1)

        args = parse_args(["--verbose", "--verbose"])

        self.assertTrue(args.verbose, 2)

        args = parse_args(["--verbose", "--verbose", "--verbose"])

        self.assertTrue(args.verbose, 3)

    def test_number(self):
        args = parse_args(["--number", "123"])

        self.assertEqual(args.number, 123)

        args = parse_args(["-n", "123"])

        self.assertEqual(args.number, 123)

        with self.assertRaises(SystemExit), redirect_stderr(StringIO()):
            parse_args(["--number", "foo"])

        with self.assertRaises(SystemExit), redirect_stderr(StringIO()):
            parse_args(["-n", "foo"])

    def test_store_runtime(self):
        args = parse_args(["--store-runtime", "cves.list"])

        self.assertEqual(args.store_runtime, Path("cves.list"))

    def test_retry_attempts(self):
        args = parse_args(["--retry-attempts", "42"])

        self.assertEqual(args.retry_attempts, 42)

        with self.assertRaises(SystemExit), redirect_stderr(StringIO()):
            parse_args(["--retry-attempts", "foo"])

    def test_nvd_api_key(self):
        args = parse_args(["--nvd-api-key", "1234"])

        self.assertEqual(args.nvd_api_key, "1234")

    def test_since(self):
        args = parse_args(["--since", "2024-01-01T15:24:17.000000+00:00"])

        self.assertEqual(
            args.since, datetime(2024, 1, 1, 15, 24, 17, tzinfo=timezone.utc)
        )
        with self.assertRaises(SystemExit), redirect_stderr(StringIO()):
            parse_args(["--since", "foo"])

    def test_since_from_file(self):
        with temp_directory() as temp_dir:
            time_file = temp_dir / "runtime"
            time_file.write_text("2024-01-01T15:24:17.000000+00:00")

            args = parse_args(["--since-from-file", str(time_file)])

            self.assertEqual(
                args.since_from_file,
                time_file,
            )

    def test_since_conflicts_since_from_file(self):
        with self.assertRaises(SystemExit), redirect_stderr(StringIO()):
            parse_args(
                [
                    "--since-from-file",
                    "foo",
                    "--since",
                    "2024-01-01T15:24:17.000000+00:00",
                ]
            )
