# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from pontos.nvd.models.cpe_match_string import CPEMatchString
from rich.console import Console

from ...cli import DEFAULT_VERBOSITY
from ...generic_cli.processor import ScapProcessor
from ...generic_cli.producer.base import BaseScapProducer
from ...generic_cli.queue import DEFAULT_QUEUE_SIZE
from ...generic_cli.worker.base import BaseScapWorker

CPE_MATCH_TYPE_PLURAL = "CPE match strings"
CPE_MATCH_DEFAULT_CHUNK_SIZE = 500


class CpeMatchProcessor(ScapProcessor[CPEMatchString]):
    """
    Class that handles a producer object generating CPE match strings
    to be processed by a worker object.
    """

    _item_type_plural = CPE_MATCH_TYPE_PLURAL
    _arg_defaults = {
        "chunk_size": CPE_MATCH_DEFAULT_CHUNK_SIZE,
        "queue_size": DEFAULT_QUEUE_SIZE,
        "verbose": DEFAULT_VERBOSITY,
    }

    @staticmethod
    def from_args(
        args: Namespace,
        console: Console,
        error_console: Console,
        producer: BaseScapProducer,
        worker: BaseScapWorker,
    ) -> "CpeMatchProcessor":
        """
        Create a new `CPEMatchNvdApiProducer` with parameters from
         the given command line args gathered by an `ArgumentParser`.

        Args:
            args: Command line arguments to use
            console: Console for standard output.
            error_console: Console for error output.
            producer: The producer generating the CPE match strings.
            worker: The worker processing the CPE match strings.
        Returns:
            The new `CpeMatchProcessor`.
        """
        return CpeMatchProcessor(
            console,
            error_console,
            producer,
            worker,
            queue_size=args.queue_size,
            chunk_size=args.chunk_size,
            verbose=args.verbose,
        )

    def __init__(
        self,
        console: Console,
        error_console: Console,
        producer: BaseScapProducer,
        worker: BaseScapWorker,
        *,
        queue_size: int | None = None,
        chunk_size: int | None = None,
        verbose: int | None = None,
    ):
        """
        Constructor for a new CPE match string processor.

        Args:
            console: Console for standard output.
            error_console: Console for error output.
            producer: The producer generating the CPE match strings.
            worker: The worker processing the CPE match strings.
            queue_size: The number of chunks allowed in the queue.
            chunk_size: The expected maximum number of CPE match strings per chunk.
            verbose: Verbosity level of log messages.
        """
        super().__init__(
            console,
            error_console,
            producer,
            worker,
            queue_size=queue_size,
            chunk_size=chunk_size,
            verbose=verbose,
        )
