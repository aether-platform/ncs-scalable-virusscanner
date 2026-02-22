from abc import ABC, abstractmethod


class DataProvider(ABC):
    @abstractmethod
    def push_chunk(self, chunk: bytes):
        pass

    @abstractmethod
    def finalize_push(self):
        pass

    @abstractmethod
    def get_data(self) -> bytes:
        pass
