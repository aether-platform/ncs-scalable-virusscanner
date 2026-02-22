from abc import ABC, abstractmethod
from typing import Any, List, Optional, Set, Tuple


class QueueProvider(ABC):
    """
    Abstract base class for message queue operations.
    Enables swapping Redis with other backends (e.g., RabbitMQ, SQS, NATS, Kafka).
    """

    @abstractmethod
    def push(self, queue_name: str, payload: bytes | str):
        """Pushes a message onto a queue."""
        pass

    @abstractmethod
    def pop(
        self, queue_names: List[str], timeout: int = 0
    ) -> Optional[Tuple[str, bytes]]:
        """Blocks until a message is available from one of the queues."""
        pass


class StateStoreProvider(ABC):
    """
    Abstract base class for Key-Value and Set operations.
    Enables swapping Redis with other backends (e.g., Memcached, etcd, DynamoDB).
    """

    @abstractmethod
    def set(
        self, key: str, value: bytes | str, ex: int = None, nx: bool = False
    ) -> bool | None:
        """Sets a key-value pair with an optional expiration and NX flag."""
        pass

    @abstractmethod
    def get(self, key: str) -> Optional[bytes]:
        """Retrieves the value for a given key."""
        pass

    @abstractmethod
    def mget(self, *keys: str) -> List[Optional[bytes]]:
        """Retrieves values for multiple keys."""
        pass

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Checks if a key exists."""
        pass

    @abstractmethod
    def delete(self, key: str):
        """Deletes a key-value pair."""
        pass

    @abstractmethod
    def sadd(self, name: str, *values: str) -> int:
        """Adds values to a set."""
        pass

    @abstractmethod
    def srem(self, name: str, *values: str) -> int:
        """Removes values from a set."""
        pass

    @abstractmethod
    def smembers(self, name: str) -> Set[bytes]:
        """Retrieves all members of a set."""
        pass


class RedisQueueProvider(QueueProvider):
    """
    Redis implementation of the QueueProvider.
    """

    def __init__(self, redis_client: Any):
        self.redis = redis_client

    def push(self, queue_name: str, payload: bytes | str):
        self.redis.lpush(queue_name, payload)

    def pop(
        self, queue_names: List[str], timeout: int = 0
    ) -> Optional[Tuple[str, bytes]]:
        res = self.redis.brpop(queue_names, timeout=timeout)
        if res:
            # brpop returns (queue_name_bytes, payload_bytes)
            return res[0].decode("utf-8"), res[1]
        return None


class RedisStateStoreProvider(StateStoreProvider):
    """
    Redis implementation of the StateStoreProvider.
    """

    def __init__(self, redis_client: Any):
        self.redis = redis_client

    def set(
        self, key: str, value: bytes | str, ex: int = None, nx: bool = False
    ) -> bool | None:
        return self.redis.set(key, value, ex=ex, nx=nx)

    def get(self, key: str) -> Optional[bytes]:
        return self.redis.get(key)

    def mget(self, *keys: str) -> List[Optional[bytes]]:
        if not keys:
            return []
        return self.redis.mget(*keys)

    def exists(self, key: str) -> bool:
        return bool(self.redis.exists(key))

    def delete(self, key: str):
        self.redis.delete(key)

    def sadd(self, name: str, *values: str) -> int:
        if not values:
            return 0
        return self.redis.sadd(name, *values)

    def srem(self, name: str, *values: str) -> int:
        if not values:
            return 0
        return self.redis.srem(name, *values)

    def smembers(self, name: str) -> Set[bytes]:
        return self.redis.smembers(name)
