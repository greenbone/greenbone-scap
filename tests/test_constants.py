# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from json import JSONDecodeError

from pontos.github.api import HTTPError

from greenbone.scap.constants import STAMINA_API_RETRY_EXCEPTIONS


class RetryExceptionsTestCase(unittest.TestCase):
    def test_http_errors_are_retried(self):
        self.assertEqual(
            STAMINA_API_RETRY_EXCEPTIONS,
            (JSONDecodeError, HTTPError),
        )
