from abc import ABC, abstractmethod
from typing import Any, List, Optional, Set, Tuple


class QueueProvider(ABC):
    """
    Abstract base class for message queue operations.
    Enables swapping Redis with other backends (e.g., RabbitMQ, SQS, NATS, Kafka).
    """

    @abstractmethod
    async def push(self, queue_name: str, payload: bytes | str):
        """Pushes a message onto a queue."""
        pass

    @abstractmethod
    async def pop(
        self, queue_names: List[str], timeout: int = 0
    ) -> Optional[Tuple[str, bytes]]:
        """Blocks until a message is available from one of the queues."""
        pass

    async def expire(self, key: str, seconds: int) -> bool:
        """Sets a TTL on a key. Default no-op for backends without expiry."""
        return True


class StateStoreProvider(ABC):
    """
    Abstract base class for Key-Value and Set operations.
    Enables swapping Redis with other backends (e.g., Memcached, etcd, DynamoDB).
    """

    @abstractmethod
    async def set(
        self, key: str, value: bytes | str, ex: int = None, nx: bool = False
    ) -> bool | None:
        """Sets a key-value pair with an optional expiration and NX flag."""
        pass

    @abstractmethod
    async def get(self, key: str) -> Optional[bytes]:
        """Retrieves the value for a given key."""
        pass

    @abstractmethod
    async def mget(self, *keys: str) -> List[Optional[bytes]]:
        """Retrieves values for multiple keys."""
        pass

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Checks if a key exists."""
        pass

    @abstractmethod
    async def delete(self, key: str):
        """Deletes a key-value pair."""
        pass

    @abstractmethod
    async def sadd(self, name: str, *values: str) -> int:
        """Adds values to a set."""
        pass

    @abstractmethod
    async def srem(self, name: str, *values: str) -> int:
        """Removes values from a set."""
        pass

    @abstractmethod
    async def smembers(self, name: str) -> Set[bytes]:
        """Retrieves all members of a set."""
        pass


class RedisQueueProvider(QueueProvider):
    """
    Redis implementation of the QueueProvider.
    """

    def __init__(self, redis_client: Any):
        self.redis = redis_client

    async def push(self, queue_name: str, payload: bytes | str):
        await self.redis.lpush(queue_name, payload)

    async def pop(
        self, queue_names: List[str], timeout: int = 0
    ) -> Optional[Tuple[str, bytes]]:
        res = await self.redis.brpop(queue_names, timeout=timeout)
        if res:
            # brpop returns (queue_name_bytes, payload_bytes)
            return res[0].decode("utf-8"), res[1]
        return None

    async def expire(self, key: str, seconds: int) -> bool:
        return await self.redis.expire(key, seconds)


class RedisStateStoreProvider(StateStoreProvider):
    """
    Redis implementation of the StateStoreProvider.
    """

    def __init__(self, redis_client: Any):
        self.redis = redis_client

    async def set(
        self, key: str, value: bytes | str, ex: int = None, nx: bool = False
    ) -> bool | None:
        return await self.redis.set(key, value, ex=ex, nx=nx)

    async def get(self, key: str) -> Optional[bytes]:
        return await self.redis.get(key)

    async def mget(self, *keys: str) -> List[Optional[bytes]]:
        if not keys:
            return []
        return await self.redis.mget(*keys)

    async def exists(self, key: str) -> bool:
        return bool(await self.redis.exists(key))

    async def delete(self, key: str):
        await self.redis.delete(key)

    async def sadd(self, name: str, *values: str) -> int:
        if not values:
            return 0
        return await self.redis.sadd(name, *values)

    async def srem(self, name: str, *values: str) -> int:
        if not values:
            return 0
        return await self.redis.srem(name, *values)

    async def smembers(self, name: str) -> Set[bytes]:
        return await self.redis.smembers(name)
