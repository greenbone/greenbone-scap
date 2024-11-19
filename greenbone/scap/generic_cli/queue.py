# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
from typing import Generic, Sequence, TypeVar

T = TypeVar("T")
"Generic type variable for the type of SCAP items handled"

DEFAULT_QUEUE_SIZE = 3
"Default number of chunks allowed in the queue"

DEFAULT_CHUNK_SIZE = 100
"Default expected maximum number of SCAP items per chunk"


class ScapChunkQueue(Generic[T]):
    """
    A queue for passing SCAP data from a producer to a worker processing it.

    Producers should set the expected total number in their
    (`fetch_initial_data`) method and add new chunks in their main loop
    (`run_loop`) using `put_chunk`.
    Once there are no more chunks to be added, the producer must signal this
    by calling `set_producer_finished`.

    Workers processing the chunks should fetch them inside their `run_loop`
    with `get_chunk` while more chunks are expected according to
    `more_chunks_expected` and call `chunk_processed` after processing
    each chunk.

    The type of the items can be set by the generic type,
    e.g. `ScapChunkQueue[CPE]` will be a queue handling chunks of CPE objects.
    """

    def __init__(
        self,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ):
        """
        Creates a new SCAP chunk queue
        Args:
            queue_size: The maximum number of chunks that can be in the queue.
            chunk_size: The expected number of SCAP items per chunk.
        """
        self.chunk_size = chunk_size
        "The expected maximum number of SCAP items per chunk."

        self.total_items: int = 1
        "total_items: The expected total number of SCAP items."

        self._queue: asyncio.Queue[Sequence[T]] = asyncio.Queue(queue_size)
        "Internal queue data structure for holding the chunks of SCAP items."

        self._producer_finished_event = asyncio.Event()
        "Event to be set when the producer will no longer add chunks to the queue"

    async def put_chunk(self, chunk: Sequence[T]) -> None:
        """
        Adds a chunk of SCAP items to the queue, blocking if the queue is full.

        Args:
             chunk: The chunk (sequence of SCAP items) to put into the queue.
        """

        await self._queue.put(chunk)

    async def get_chunk(self) -> Sequence[T]:
        """
        Gets and removes the next chunk of SCAP items from the queue,
        blocking if the queue is empty.

        Returns:
             The next chunk (sequence of SCAP items).
        """
        return await self._queue.get()

    def chunk_processed(self) -> None:
        """
        Signal that a chunk fetched from the queue has been processed.
        """
        self._queue.task_done()

    def more_chunks_expected(self) -> bool:
        """
        Checks if more chunks can be fetched, i.e. the "producer finished" event is not set
        and the queue is not empty.

        Returns:
             True if the event is set, False otherwise
        """
        return not (
            self._producer_finished_event.is_set() and self._queue.empty()
        )

    def set_producer_finished(self) -> None:
        """
        Sets the "producer finished" event flag.
        """
        self._producer_finished_event.set()

    async def join(self) -> None:
        """
        Blocks until all chunks in the queue are fetched and processed.
        """
        await self._queue.join()
