import abc
from typing import Any, Iterator, Optional, Protocol


class RedisClient(Protocol):
    """Protocol for Redis client to decouple providers from the concrete redis.Redis class."""

    def blmove(
        self,
        src: str,
        dest: str,
        timeout: int,
        src_at: str = "LEFT",
        dest_at: str = "RIGHT",
    ) -> Optional[bytes]: ...

    def get(self, key: str) -> Optional[Any]: ...

    def set(self, key: str, value: Any, ex: Optional[int] = None) -> Any: ...

    def rpush(self, key: str, *values: Any) -> int: ...

    def delete(self, *keys: str) -> int: ...

    def expire(self, key: str, time: int) -> bool: ...


class DataProvider(abc.ABC):
    @abc.abstractmethod
    def get_chunks(self) -> Iterator[bytes]:
        """Returns an iterator of binary chunks."""
        pass

    @abc.abstractmethod
    def push_chunk(self, chunk: bytes):
        """Pushes a chunk of data (Producer side)."""
        pass

    @abc.abstractmethod
    def finalize_push(self):
        """Finalizes the data push (Producer side)."""
        pass

    @abc.abstractmethod
    def finalize(self, success: bool, is_virus: bool):
        """Called after scanning is complete."""
        pass

    @abc.abstractmethod
    def get_data_key(self) -> Optional[str]:
        """Returns a key for the client to retrieve verified data, if applicable."""
        pass
