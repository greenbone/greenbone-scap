# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import unittest

RUN_INTEGRATION_TESTS = (
    os.environ.get("RUN_INTEGRATION_TESTS", "false").lower() == "true"
)

RUN_ALL_TESTS = os.environ.get("RUN_ALL_TESTS", "false").lower() == "true"

Integration_test = unittest.skipUnless(
    RUN_INTEGRATION_TESTS or RUN_ALL_TESTS, "Skipping integration test"
)

Unit_test = unittest.skipIf(
    RUN_INTEGRATION_TESTS and not RUN_ALL_TESTS, "Skipping unit test"
)
