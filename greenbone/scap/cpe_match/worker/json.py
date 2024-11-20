# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace
from pathlib import Path
from typing import Sequence

from pontos.nvd.models.cpe_match_string import CPEMatchString
from rich.console import Console
from rich.progress import Progress

from ...generic_cli.worker.json import ScapJsonWriteWorker
from ..cli.processor import CPE_MATCH_TYPE_PLURAL
from ..json import MatchStringJsonManager


class CpeMatchJsonWriteWorker(ScapJsonWriteWorker[CPEMatchString]):
    """
    Async context manager base class for a worker writing
    CPE match strings to a single JSON file.
    """

    _item_type_plural = CPE_MATCH_TYPE_PLURAL
    "Plural form of the type of items to use in log messages."

    _arg_defaults = ScapJsonWriteWorker._arg_defaults
    "Default values for optional arguments."

    @classmethod
    def from_args(
        cls,
        args: Namespace,
        console: Console,
        error_console: Console,
        progress: Progress,
    ) -> "CpeMatchJsonWriteWorker":
        """
        Create a new `CpeMatchJsonWriteWorker` with parameters from
         the given command line args gathered by an `ArgumentParser`.

        Args:
            args: Command line arguments to use
            console: Console for standard output.
            error_console: Console for error output.
            progress: Progress bar renderer to be updated by the worker.

        Returns:
            The new `CpeMatchJsonWriteWorker`.
        """
        return CpeMatchJsonWriteWorker(
            console,
            error_console,
            progress,
            storage_path=args.storage_path or cls._arg_defaults["storage_path"],
            schema_path=args.schema_path or cls._arg_defaults["schema_path"],
            compress=args.compress if not None else False,
            verbose=args.verbose or 0,
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
        super().__init__(
            console,
            error_console,
            progress,
            storage_path=storage_path,
            schema_path=schema_path,
            compress=compress,
            verbose=verbose,
        )

        self._json_manager = MatchStringJsonManager(
            error_console,
            storage_path,
            compress=compress,
            schema_path=schema_path,
            raise_error_on_validation=False,
        )
        "Manager object handling saving the CPE match strings to a JSON file"

    async def _handle_chunk(self, chunk: Sequence[CPEMatchString]):
        """
        Callback handling a chunk of CPE match strings from the queue.

        Adds the CPE match strings in the chunk to the document model.

        Args:
            chunk: The last chunk fetched from the queue.
        """
        self._json_manager.add_match_strings(chunk)

    async def _loop_end(self) -> None:
        """
        Callback handling the exiting the main worker loop.

        Makes the JSON manager write the document to the file.
        """
        self._json_manager.write()
        await super()._loop_end()
