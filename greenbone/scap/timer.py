# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import time
from contextlib import AbstractContextManager
from types import TracebackType
from typing import Self


class TimerError(Exception):
    pass


class Timer(AbstractContextManager):
    def __init__(self) -> None:
        self._start_time: float | None = None
        self.elapsed_time: float | None = None

    def start(self) -> Self:
        """Start a new timer"""

        if self._start_time is not None:
            raise TimerError("Timer is already running.")

        self._start_time = time.perf_counter()
        return self

    def stop(self) -> float:
        """Stop the timer, and report the elapsed time"""

        if self._start_time is None:
            raise TimerError("Timer is not running.")

        self.elapsed_time = time.perf_counter() - self._start_time

        self._start_time = None
        return self.elapsed_time

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(
        self,
        /,
        __exc_type: type[BaseException] | None,
        __exc_value: BaseException | None,
        __traceback: TracebackType | None,
    ) -> None:
        self.stop()
