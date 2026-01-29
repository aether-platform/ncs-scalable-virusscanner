from typing import Iterator, Optional

from .base import DataProvider


class InlineStreamProvider(DataProvider):
    def __init__(self, data: bytes = b""):
        self.data = data

    def get_chunks(self) -> Iterator[bytes]:
        chunk_size = 4096
        for i in range(0, len(self.data), chunk_size):
            yield self.data[i : i + chunk_size]

    def push_chunk(self, chunk: bytes):
        self.data += chunk

    def finalize_push(self):
        pass

    def finalize(self, success: bool, is_virus: bool):
        pass

    def get_data_key(self) -> Optional[str]:
        return None
