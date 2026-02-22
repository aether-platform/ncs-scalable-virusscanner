from typing import AsyncIterator, Optional

from .base import DataProvider, RedisClient


class RedisStreamProvider(DataProvider):
    def __init__(self, redis_client: RedisClient, chunks_key: str):
        self.redis = redis_client
        self.chunks_key = chunks_key
        self.verified_key = f"{chunks_key}:verified"
        self.done_key = f"{chunks_key}:done"

    async def get_chunks(self) -> AsyncIterator[bytes]:
        await self.redis.delete(self.verified_key)
        while True:
            # BLMOVE for real-time follower scanning
            chunk = await self.redis.blmove(
                self.chunks_key, self.verified_key, timeout=5, src="LEFT", dest="RIGHT"
            )
            if not chunk:
                if await self.redis.get(self.done_key):
                    break
                continue
            yield chunk

    async def push_chunk(self, chunk: bytes):
        await self.redis.rpush(self.chunks_key, chunk)

    async def finalize_push(self):
        await self.redis.set(self.done_key, "1")

    async def finalize(self, success: bool, is_virus: bool):
        if not success or is_virus:
            await self.redis.delete(self.verified_key)
        else:
            await self.redis.expire(self.verified_key, 3600)
        await self.redis.delete(self.done_key)

    def get_data_key(self) -> Optional[str]:
        return self.verified_key
