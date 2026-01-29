from typing import Iterator, Optional

from .base import DataProvider, RedisClient


class RedisStreamProvider(DataProvider):
    def __init__(self, redis_client: RedisClient, chunks_key: str):
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

    def push_chunk(self, chunk: bytes):
        self.redis.rpush(self.chunks_key, chunk)

    def finalize_push(self):
        self.redis.set(self.done_key, "1")

    def finalize(self, success: bool, is_virus: bool):
        if not success or is_virus:
            self.redis.delete(self.verified_key)
        else:
            self.redis.expire(self.verified_key, 3600)
        self.redis.delete(self.done_key)

    def get_data_key(self) -> Optional[str]:
        return self.verified_key
