# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from time import sleep

from greenbone.scap.timer import Timer, TimerError
from tests.tags import Unit_test


@Unit_test
class TimerTestCase(unittest.TestCase):
    def test_context_manager(self):
        t = Timer()
        with t as t:
            sleep(0.1)

        self.assertIsNotNone(t.elapsed_time)

        with t as t:
            sleep(0.1)

        self.assertIsNotNone(t.elapsed_time)

    def test_timer(self):
        t = Timer()
        t.start()
        sleep(0.1)

        self.assertIsNotNone(t.stop())
        self.assertIsNotNone(t.elapsed_time)

        t.start()
        sleep(0.1)

        self.assertIsNotNone(t.stop())
        self.assertIsNotNone(t.elapsed_time)

    def test_start_twice(self):
        t = Timer()
        t.start()

        with self.assertRaises(TimerError):
            t.start()

    def test_stop_not_started(self):
        t = Timer()

        with self.assertRaises(TimerError):
            t.stop()
