import os
from typing import Iterator, Optional

from .base import DataProvider


class SharedDiskStreamProvider(DataProvider):
    def __init__(self, file_path: str, delete_after: bool = True):
        self.file_path = file_path
        self.delete_after = delete_after

    def get_chunks(self) -> Iterator[bytes]:
        if not os.path.exists(self.file_path):
            return

        with open(self.file_path, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                yield chunk

    def push_chunk(self, chunk: bytes):
        mode = "ab" if os.path.exists(self.file_path) else "wb"
        with open(self.file_path, mode) as f:
            f.write(chunk)

    def finalize_push(self):
        pass

    def finalize(self, success: bool, is_virus: bool):
        if self.delete_after and os.path.exists(self.file_path):
            os.remove(self.file_path)

    def get_data_key(self) -> Optional[str]:
        return None
