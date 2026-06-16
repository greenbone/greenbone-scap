# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from contextlib import redirect_stderr
from io import StringIO

from greenbone.scap.cpe.cli.find import parse_args
from tests.tags import Unit_test


@Unit_test
class ParseArgsTestCase(unittest.TestCase):
    def test_defaults(self):
        args = parse_args(["cpe"])

        self.assertFalse(args.echo_sql)
        self.assertEqual(args.verbose, 0)
        self.assertFalse(args.exact)
        self.assertIsNone(args.database_name)
        self.assertIsNone(args.database_host)
        self.assertIsNone(args.database_port)
        self.assertIsNone(args.database_user)
        self.assertIsNone(args.database_password)
        self.assertIsNone(args.database_schema)
        self.assertIsNone(args.version_start_including)
        self.assertIsNone(args.version_end_including)
        self.assertIsNone(args.version_start_excluding)
        self.assertIsNone(args.version_end_excluding)
        self.assertIsNone(args.limit)
        self.assertFalse(args.include_deprecated)

    def test_cpe(self):
        args = parse_args(["cpe"])

        self.assertEqual(args.cpe, "cpe")

    def test_database(self):
        args = parse_args(
            [
                "--database-name",
                "scap",
                "--database-host",
                "a-db-server",
                "--database-port",
                "123",
                "--database-user",
                "scap-user",
                "--database-password",
                "1234",
                "--database-schema",
                "scap-schema",
                "cpe",
            ]
        )

        self.assertEqual(args.database_name, "scap")
        self.assertEqual(args.database_host, "a-db-server")
        self.assertEqual(args.database_port, 123)
        self.assertEqual(args.database_user, "scap-user")
        self.assertEqual(args.database_password, "1234")
        self.assertEqual(args.database_schema, "scap-schema")

    def test_echo_sql(self):
        args = parse_args(["--echo-sql", "cpe"])

        self.assertTrue(args.echo_sql)

    def test_verbose(self):
        args = parse_args(["-v", "cpe"])

        self.assertTrue(args.verbose, 1)

        args = parse_args(["-vv", "cpe"])

        self.assertTrue(args.verbose, 2)

        args = parse_args(["-vvv", "cpe"])

        self.assertTrue(args.verbose, 3)

        args = parse_args(["--verbose", "cpe"])

        self.assertTrue(args.verbose, 1)

        args = parse_args(["--verbose", "--verbose", "cpe"])

        self.assertTrue(args.verbose, 2)

        args = parse_args(["--verbose", "--verbose", "--verbose", "cpe"])

        self.assertTrue(args.verbose, 3)

    def test_limit(self):
        args = parse_args(["--limit", "123", "cpe"])

        self.assertEqual(args.limit, 123)

        with self.assertRaises(SystemExit), redirect_stderr(StringIO()):
            parse_args(["--limit", "foo", "cpe"])

    def test_exact(self):
        args = parse_args(["--exact", "cpe"])

        self.assertTrue(args.exact)

    def test_include_deprecated(self):
        args = parse_args(["--include-deprecated", "cpe"])

        self.assertTrue(args.include_deprecated)

        args = parse_args(["--no-include-deprecated", "cpe"])

        self.assertFalse(args.include_deprecated)

    def test_version_start_including(self):
        args = parse_args(["--version-start-including", "1.2.3", "cpe"])

        self.assertEqual(args.version_start_including, "1.2.3")

    def test_version_end_including(self):
        args = parse_args(["--version-end-including", "1.2.3", "cpe"])

        self.assertEqual(args.version_end_including, "1.2.3")

    def test_version_start_excluding(self):
        args = parse_args(["--version-start-excluding", "1.2.3", "cpe"])

        self.assertEqual(args.version_start_excluding, "1.2.3")

    def test_version_end_excluding(self):
        args = parse_args(["--version-end-excluding", "1.2.3", "cpe"])

        self.assertEqual(args.version_end_excluding, "1.2.3")
