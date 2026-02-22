import abc
from typing import Any, AsyncIterator, Optional, Protocol


class RedisClient(Protocol):
    """Protocol for Redis client to decouple providers from the concrete redis.Redis class."""

    async def blmove(
        self,
        src: str,
        dest: str,
        timeout: int,
        src_at: str = "LEFT",
        dest_at: str = "RIGHT",
    ) -> Optional[bytes]: ...

    async def get(self, key: str) -> Optional[Any]: ...

    async def set(self, key: str, value: Any, ex: Optional[int] = None) -> Any: ...

    async def rpush(self, key: str, *values: Any) -> int: ...

    async def delete(self, *keys: str) -> int: ...

    async def expire(self, key: str, time: int) -> bool: ...


class DataProvider(abc.ABC):
    @abc.abstractmethod
    def get_chunks(self) -> AsyncIterator[bytes]:
        """Returns an async iterator of binary chunks."""
        pass

    @abc.abstractmethod
    async def push_chunk(self, chunk: bytes):
        """Pushes a chunk of data (Producer side)."""
        pass

    @abc.abstractmethod
    async def finalize_push(self):
        """Finalizes the data push (Producer side)."""
        pass

    @abc.abstractmethod
    async def finalize(self, success: bool, is_virus: bool):
        """Called after scanning is complete."""
        pass

    @abc.abstractmethod
    def get_data_key(self) -> Optional[str]:
        """Returns a key for the client to retrieve verified data, if applicable."""
        pass
