# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from pontos.nvd.models.cpe_match_string import CPEMatchString
from rich.console import Console

from ...cli import DEFAULT_VERBOSITY
from ...generic_cli.processor import ScapProcessor
from ...generic_cli.producer.base import BaseScapProducer
from ...generic_cli.queue import DEFAULT_QUEUE_SIZE, DEFAULT_CHUNK_SIZE
from ...generic_cli.worker.base import BaseScapWorker

CPE_MATCH_TYPE_PLURAL = "CPE match strings"
CPE_MATCH_DEFAULT_CHUNK_SIZE = 500


class CpeMatchProcessor(ScapProcessor[CPEMatchString]):

    item_type_plural = CPE_MATCH_TYPE_PLURAL
    arg_defaults = {
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
        super().__init__(
            console,
            error_console,
            producer,
            worker,
            queue_size=queue_size,
            chunk_size=chunk_size,
            verbose=verbose,
        )
