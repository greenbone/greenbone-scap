# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from abc import ABC
from argparse import ArgumentParser
from pathlib import Path
from typing import Type, TypeVar

from rich.console import Console
from rich.progress import Progress

from ...cli import DEFAULT_VERBOSITY
from .base import BaseScapWorker

T = TypeVar("T")
"Generic type variable for the type of SCAP items handled"


class ScapJsonWriteWorker(BaseScapWorker[T], ABC):
    """
    Abstract async context manager base class for a worker writing
    SCAP items to a single JSON file.

    The type of the SCAP items is to be specified by the generic type,
    e.g. `ScapJsonWriteWorker[CPE]` will be a producer handling CPE objects.
    """

    _item_type_plural = BaseScapWorker._item_type_plural
    "Default values for optional arguments."

    _arg_defaults = {
        "storage_path": ".",
        "schema_path": None,
        "verbose": DEFAULT_VERBOSITY,
    }
    "Default values for optional arguments."

    @classmethod
    def add_args_to_parser(
        cls: Type["ScapJsonWriteWorker"],
        parser: ArgumentParser,
    ):
        """
        Class method for adding JSON writer arguments to an
         `ArgumentParser`.

        Args:
            parser: The parser to add the arguments to.
        """
        parser.add_argument(
            "--storage-path",
            type=Path,
            help="Directory to write the JSON to. Default: %(default)s",
            default=cls._arg_defaults["storage_path"],
        )
        parser.add_argument(
            "--compress",
            action="store_true",
            default=False,
            help="Gzip compress the resulting JSON file.",
        )
        parser.add_argument(
            "--schema-path",
            default=cls._arg_defaults["schema_path"],
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
        """
        Constructor for a `ScapJsonWriteWorker`.

        Args:
            console: Console for standard output.
            error_console: Console for error output.
            progress: Progress bar renderer to be updated by the producer.
            storage_path: Path to the directory to write the JSON file into.
            schema_path: Optional path to the schema file for JSON validation.
            compress: Whether to gzip compress the JSON file.
            verbose: Verbosity level of log messages.
        """
        super().__init__(console, error_console, progress, verbose=verbose)

        self._storage_path = storage_path
        "Path to the directory to write the JSON file into."

        self._schema_path = schema_path
        "Optional path to the schema file for JSON validation."

        self._compress = compress
        "Whether to gzip compress the JSON file."

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return
