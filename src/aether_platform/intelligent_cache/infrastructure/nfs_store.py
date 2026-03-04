import json
import logging
import os
import queue as queue_mod
from typing import Optional

logger = logging.getLogger(__name__)


class NfsFileStore:
    """NFS/local filesystem backend for storing and retrieving scanned files.

    Drop-in replacement for MinioFileStore using a PersistentVolume mount.
    """

    def __init__(self, base_path: str = "/data/cache"):
        self.base_path = base_path
        os.makedirs(self.base_path, exist_ok=True)
        logger.info(f"NfsFileStore initialized at: {self.base_path}")

    def _file_path(self, object_key: str) -> str:
        return os.path.join(self.base_path, object_key)

    def _meta_path(self, object_key: str) -> str:
        return os.path.join(self.base_path, f"{object_key}.meta.json")

    def _write_metadata(self, object_key: str, metadata: Optional[dict]):
        if not metadata:
            return
        meta_path = self._meta_path(object_key)
        with open(meta_path, "w") as f:
            json.dump(metadata, f)

    def store_file(
        self, object_key: str, data: bytes, metadata: Optional[dict] = None
    ) -> str:
        """Store a file on the local filesystem. Returns the object key."""
        file_path = self._file_path(object_key)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        with open(file_path, "wb") as f:
            f.write(data)

        self._write_metadata(object_key, metadata)
        logger.info(f"Stored file on NFS: {object_key} ({len(data)} bytes)")
        return object_key

    def store_file_streamed(
        self,
        object_key: str,
        chunk_queue: queue_mod.Queue,
        metadata: Optional[dict] = None,
    ) -> Optional[str]:
        """Stream chunks from queue to a local file. Skips if file already exists.

        Reads from chunk_queue until a None sentinel is received.
        Blocks the calling thread until write completes.
        """
        if self.exists(object_key):
            while True:
                try:
                    if chunk_queue.get(timeout=300) is None:
                        break
                except queue_mod.Empty:
                    break
            logger.debug(f"File cache hit, skipped write: {object_key}")
            return None

        file_path = self._file_path(object_key)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        with open(file_path, "wb") as f:
            while True:
                try:
                    chunk = chunk_queue.get(timeout=300)
                except queue_mod.Empty:
                    logger.warning(f"Queue timeout while streaming: {object_key}")
                    break
                if chunk is None:
                    break
                f.write(chunk)

        self._write_metadata(object_key, metadata)
        logger.info(f"Streamed file to NFS: {object_key}")
        return object_key

    def retrieve_file(self, object_key: str) -> Optional[bytes]:
        """Retrieve a file from the local filesystem. Returns None if not found."""
        file_path = self._file_path(object_key)
        if not os.path.isfile(file_path):
            return None
        with open(file_path, "rb") as f:
            return f.read()

    def exists(self, object_key: str) -> bool:
        """Check if a file exists on the local filesystem."""
        return os.path.isfile(self._file_path(object_key))
