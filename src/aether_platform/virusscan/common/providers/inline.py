from typing import AsyncIterator, Optional

from .base import DataProvider


class InlineStreamProvider(DataProvider):
    def __init__(self, data: bytes = b""):
        self.data = data

    async def get_chunks(self) -> AsyncIterator[bytes]:
        chunk_size = 4096
        for i in range(0, len(self.data), chunk_size):
            yield self.data[i : i + chunk_size]

    async def push_chunk(self, chunk: bytes):
        self.data += chunk

    async def finalize_push(self):
        pass

    async def finalize(self, success: bool, is_virus: bool):
        pass

    def get_data_key(self) -> Optional[str]:
        return None
