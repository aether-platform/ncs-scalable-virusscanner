from .base import DataProvider


class RedisStreamProvider(DataProvider):
    def __init__(self, redis_client, chunks_key: str):
        self.redis = redis_client
        self.chunks_key = chunks_key
        self.ttl = 300

    def push_chunk(self, chunk: bytes):
        self.redis.append(f"data:{self.chunks_key}", chunk)
        self.redis.expire(f"data:{self.chunks_key}", self.ttl)

    def finalize_push(self):
        # No specific action needed for redis append
        pass

    def get_data(self) -> bytes:
        return self.redis.get(f"data:{self.chunks_key}")
