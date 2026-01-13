# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import unittest

RUN_INTEGRATION_TESTS = (
    os.environ.get("RUN_INTEGRATION_TESTS", "false").lower() == "true"
)

Integration_test = unittest.skipUnless(
    RUN_INTEGRATION_TESTS, "Skipping integration test"
)
