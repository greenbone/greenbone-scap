# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from pontos.github.api import HTTPStatusError, Request, Response
from rich.console import Console

from greenbone.scap.cli import CLIRunner


class CLIRunnerTestCase(unittest.TestCase):
    def test_http_status_error(self):
        async def failing_request(
            console: Console, error_console: Console
        ) -> None:
            request = Request("GET", "https://example.com")
            response = Response(404, request=request)
            raise HTTPStatusError(
                "Not Found", request=request, response=response
            )

        with self.assertRaises(SystemExit) as context:
            CLIRunner.run(failing_request)

        self.assertEqual(context.exception.code, 3)
