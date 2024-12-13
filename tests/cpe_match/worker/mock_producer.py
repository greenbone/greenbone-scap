# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime
from uuid import UUID, uuid4

from pontos.nvd.models.cpe_match_string import CPEMatchString
from rich.console import Console
from rich.progress import Progress

from greenbone.scap.generic_cli.producer.base import BaseScapProducer


def uuid_replace_str(uuid: UUID, iteration: int, number: int) -> str:
    id_str = str(uuid).rsplit("-", 2)
    return f"{id_str[0]}-{iteration:04}-{number:012}"


def uuid_replace(uuid: UUID, iteration: int, number: int) -> UUID:
    return UUID(uuid_replace_str(uuid, iteration, number))


def generate_cpe_name(iteration: int, number: int) -> str:
    return f"cpe:2.3:a:acme:test-app:1.{iteration-1}.{number-1}:*:*:*:*:*:*:*"


class CpeMatchMockProducer(BaseScapProducer[CPEMatchString]):
    def __init__(
        self,
        console: Console,
        error_console: Console,
        progress: Progress,
        num_chunks: int,
        chunk_size: int,
        minimal_cpe_match_strings: bool = False,
    ):
        super().__init__(
            console=console,
            error_console=error_console,
            progress=progress,
        )
        self.num_chunks: int = num_chunks
        self.chunk_size: int = chunk_size
        self.initial_data_fetched: bool = False
        self.context_entered: bool = False
        self.context_exited: bool = False
        self.base_match_criteria_id: UUID = uuid4()
        self.minimal_cpe_match_strings: bool = minimal_cpe_match_strings

    def generate_chunk(self, chunk_index: int):
        chunk = []
        for item_index in range(self.chunk_size):
            match_criteria_id = uuid_replace(
                self.base_match_criteria_id, chunk_index, item_index
            )
            cpe_name = generate_cpe_name(chunk_index, item_index)
            now = datetime.now()

            new_cpe_match_string = CPEMatchString(
                match_criteria_id=match_criteria_id,
                criteria=cpe_name,
                status="Active",
                created=now,
                last_modified=now,
                cpe_last_modified=(
                    None if self.minimal_cpe_match_strings else now
                ),
            )
            chunk.append(new_cpe_match_string)

        return chunk

    async def fetch_initial_data(self) -> int:
        return self.num_chunks * self.chunk_size

    async def run_loop(self) -> None:
        try:
            for chunk_index in range(self.num_chunks):
                await self._queue.put_chunk(self.generate_chunk(chunk_index))
        finally:
            self._queue.set_producer_finished()

    async def __aenter__(self):
        self.context_entered = True

    async def __aexit__(self, __exc_type, __exc_value, __traceback):
        self.context_exited = True
