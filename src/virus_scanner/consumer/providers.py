import abc
import os
from typing import Iterator, Optional

import redis


class DataProvider(abc.ABC):
    @abc.abstractmethod
    def get_chunks(self) -> Iterator[bytes]:
        """Returns an iterator of binary chunks."""
        pass

    @abc.abstractmethod
    def finalize(self, success: bool, is_virus: bool):
        """Called after scanning is complete."""
        pass

    @abc.abstractmethod
    def get_data_key(self) -> Optional[str]:
        """Returns a key for the client to retrieve verified data, if applicable."""
        pass


class RedisStreamProvider(DataProvider):
    def __init__(self, redis_client: redis.Redis, chunks_key: str):
        self.redis = redis_client
        self.chunks_key = chunks_key
        self.verified_key = f"{chunks_key}:verified"
        self.done_key = f"{chunks_key}:done"

    def get_chunks(self) -> Iterator[bytes]:
        self.redis.delete(self.verified_key)
        while True:
            # BLMOVE for real-time follower scanning
            chunk = self.redis.blmove(
                self.chunks_key, self.verified_key, timeout=5, src="LEFT", dest="RIGHT"
            )
            if not chunk:
                if self.redis.get(self.done_key):
                    break
                continue
            yield chunk

    def finalize(self, success: bool, is_virus: bool):
        if not success or is_virus:
            self.redis.delete(self.verified_key)
        else:
            self.redis.expire(self.verified_key, 3600)
        self.redis.delete(self.done_key)

    def get_data_key(self) -> Optional[str]:
        return self.verified_key


class LocalFileProvider(DataProvider):
    def __init__(self, file_path: str, delete_after: bool = True):
        self.file_path = file_path
        self.delete_after = delete_after

    def get_chunks(self) -> Iterator[bytes]:
        with open(self.file_path, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                yield chunk

    def finalize(self, success: bool, is_virus: bool):
        if self.delete_after and os.path.exists(self.file_path):
            os.remove(self.file_path)

    def get_data_key(self) -> Optional[str]:
        return None


class BodyProvider(DataProvider):
    def __init__(self, data: bytes):
        self.data = data

    def get_chunks(self) -> Iterator[bytes]:
        chunk_size = 4096
        for i in range(0, len(self.data), chunk_size):
            yield self.data[i : i + chunk_size]

    def finalize(self, success: bool, is_virus: bool):
        pass

    def get_data_key(self) -> Optional[str]:
        return None
