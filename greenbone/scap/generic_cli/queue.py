# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
from typing import Generic, Sequence, TypeVar

T = TypeVar("T")

DEFAULT_QUEUE_SIZE = 3
DEFAULT_CHUNK_SIZE = 100


class ScapChunkQueue(Generic[T]):
    """
    A queue for passing SCAP data from a producer to a worker processing it.
    """

    def __init__(
        self,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ):
        self.queue: asyncio.Queue[Sequence[T]] = asyncio.Queue(queue_size)
        self.chunk_size = chunk_size

        self.producer_finished_event = asyncio.Event()
        self.total_items: int = 1

    async def put_chunk(self, chunk: Sequence[T]) -> None:
        """
        Adds a chunk of SCAP items to the queue, blocking if the queue is full.

        :param chunk: The chunk (sequence of SCAP items) to put into the queue.
        """
        await self.queue.put(chunk)

    async def get_chunk(self) -> Sequence[T]:
        """
        Gets and removes the next chunk of SCAP items from the queue,
        blocking if the queue is empty.

        :return: The next chunk (sequence of SCAP items).
        """
        return await self.queue.get()

    def more_chunks_expected(self) -> bool:
        """
        Checks if more chunks can be fetched, i.e. the "producer finished" event is not set
        and the queue is not empty.

        :return: True if the event is set, False otherwise
        """
        return not (
            self.producer_finished_event.is_set() and self.queue.empty()
        )

    def set_producer_finished(self):
        """
        Sets the "producer finished" event flag.
        """
        self.producer_finished_event.set()

    async def join(self):
        await self.queue.join()

    def task_done(self):
        self.queue.task_done()
