# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from greenbone.scap.version import canonical_version, is_valid_version
from tests.tags import Unit_test


@Unit_test
class CanonicalVersionTestCase(unittest.TestCase):
    def test_invalid_version(self):
        self.assertIsNone(canonical_version("a.b"))
        self.assertIsNone(canonical_version("1.0def"))

    def test_canonical_version(self):
        self.assertEqual(canonical_version("1.2.3"), "1.2.3")
        self.assertEqual(canonical_version("1.2.3a1"), "1.2.3")
        self.assertEqual(canonical_version("1.2.3b1"), "1.2.3")
        self.assertEqual(canonical_version("1.2.3-rc1"), "1.2.3")
        self.assertEqual(canonical_version("1.2.3.dev1"), "1.2.3")


@Unit_test
class IsValidVersionTestCase(unittest.TestCase):
    def test_invalid_version(self):
        self.assertFalse(is_valid_version(None))
        self.assertFalse(is_valid_version(""))
        self.assertFalse(is_valid_version("a.b"))
        self.assertFalse(is_valid_version("1.0def"))

    def test_valid_version(self):
        self.assertTrue(is_valid_version("1.2.3"))
        self.assertTrue(is_valid_version("1.2.3a1"))
        self.assertTrue(is_valid_version("1.2.3b1"))
        self.assertTrue(is_valid_version("1.2.3-rc1"))
        self.assertTrue(is_valid_version("1.2.3.dev1"))
