# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later


import asyncio
import sys
from collections.abc import Callable, Coroutine
from typing import Any, NoReturn, TypeAlias

from httpx2 import HTTPStatusError
from rich.console import Console

from .errors import ScapError
from .timer import Timer

DEFAULT_RETRIES = 20
DEFAULT_SQLITE_CPE_DATABASE_NAME = "cpes.db"
DEFAULT_SQLITE_CVE_DATABASE_NAME = "cves.db"
DEFAULT_POSTGRES_USER = "scap"
DEFAULT_POSTGRES_HOST = "localhost"
DEFAULT_POSTGRES_PORT = 5432
DEFAULT_POSTGRES_DATABASE_NAME = "scap"
DEFAULT_VERBOSITY = 0


class CLIError(ScapError):
    pass


RunnerFunc: TypeAlias = Callable[
    [Console, Console], Coroutine[Any, Any, int | None]
]


class CLI:
    def __init__(self, console: Console, error_console: Console) -> None:
        self.console = console
        self.error_console = error_console

    async def run(self) -> int | None: ...


class CLIRunner:
    @staticmethod
    def run(func: RunnerFunc | type[CLI]) -> NoReturn:
        console = Console(log_path=False)
        error_console = Console(file=sys.stderr, log_path=False)
        try:
            with Timer() as timer:
                if isinstance(func, type):
                    cli = func(console, error_console)
                    asyncio.run(cli.run())
                else:
                    asyncio.run(func(console, error_console))

            console.log(
                f"Done. Elapsed time: {timer.elapsed_time:0.4f} seconds"
            )
            sys.exit(0)
        except KeyboardInterrupt:
            # just exit
            sys.exit(1)
        except ScapError as e:
            error_console.print(f"Error: {e}")
            sys.exit(2)
        except HTTPStatusError as e:
            if e.response.is_client_error:
                # the error is in the response message header
                error_console.print(
                    f"Failed HTTP request. {e.response.status_code} for URL "
                    f"{e.request.url}. Error message was "
                    f"{e.response.headers.get('message')}"
                )
            else:
                error_console.print(
                    f"Failed HTTP request. {e.response.status_code} for URL "
                    f"{e.request.url}. Response was {e.response.text}"
                )
            sys.exit(3)
