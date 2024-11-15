# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from abc import ABC
from argparse import ArgumentParser
from pathlib import Path
from typing import TypeVar

from rich.console import Console
from rich.progress import Progress

from ...cli import DEFAULT_VERBOSITY
from .base import BaseScapWorker

T = TypeVar("T")


class ScapJsonWriteWorker(BaseScapWorker[T], ABC):
    item_type_plural = BaseScapWorker.item_type_plural
    arg_defaults = {
        "storage_path": ".",
        "schema_path": None,
        "verbose": DEFAULT_VERBOSITY,
    }

    @classmethod
    def add_args_to_parser(
        cls: type,
        parser: ArgumentParser,
    ):
        parser.add_argument(
            "--storage-path",
            type=Path,
            help="Directory to write the JSON to. Default: %(default)s",
            default=cls.arg_defaults["storage_path"],
        )
        parser.add_argument(
            "--compress",
            action="store_true",
            default=False,
            help="Gzip compress the resulting JSON file.",
        )
        parser.add_argument(
            "--schema-path",
            default=cls.arg_defaults["schema_path"],
            type=Path,
            help="Json schema file path. Default: %(default)s.",
        )

    def __init__(
        self,
        console: Console,
        error_console: Console,
        progress: Progress,
        *,
        storage_path: Path,
        schema_path: Path | None = None,
        compress: bool = False,
        verbose: int | None = None,
    ):
        super().__init__(console, error_console, progress, verbose=verbose)
        self._storage_path = storage_path
        self._schema_path = schema_path
        self._compress = compress

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return
