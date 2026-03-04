import io
import logging
import queue as queue_mod
from typing import Optional

from minio import Minio
from minio.error import S3Error

logger = logging.getLogger(__name__)


class _QueueStream(io.RawIOBase):
    """Readable stream backed by a thread-safe queue for streaming to MinIO."""

    def __init__(self, q: queue_mod.Queue):
        self._queue = q
        self._buf = b""
        self._eof = False

    def readable(self):
        return True

    def readinto(self, b):
        if self._eof:
            return 0
        while not self._buf:
            chunk = self._queue.get()
            if chunk is None:
                self._eof = True
                return 0
            self._buf = chunk
        n = min(len(b), len(self._buf))
        b[:n] = self._buf[:n]
        self._buf = self._buf[n:]
        return n


class MinioFileStore:
    """MinIO client wrapper for storing and retrieving scanned files."""

    def __init__(
        self,
        endpoint: str,
        access_key: str,
        secret_key: str,
        bucket: str,
        secure: bool = False,
    ):
        self.client = Minio(
            endpoint,
            access_key=access_key,
            secret_key=secret_key,
            secure=secure,
        )
        self.bucket = bucket
        self._ensure_bucket()

    def _ensure_bucket(self):
        try:
            if not self.client.bucket_exists(self.bucket):
                self.client.make_bucket(self.bucket)
                logger.info(f"Created MinIO bucket: {self.bucket}")
        except S3Error as e:
            logger.error(f"Failed to ensure bucket '{self.bucket}': {e}")

    def store_file(
        self, object_key: str, data: bytes, metadata: Optional[dict] = None
    ) -> str:
        """Store a file in MinIO (one-shot). Returns the object key."""
        metadata = dict(metadata) if metadata else {}
        content_type = metadata.pop("content_type", "application/octet-stream")
        stream = io.BytesIO(data)
        self.client.put_object(
            self.bucket,
            object_key,
            stream,
            length=len(data),
            content_type=content_type,
            metadata=metadata,
        )
        logger.info(f"Stored file in MinIO: {object_key} ({len(data)} bytes)")
        return object_key

    def store_file_streamed(
        self,
        object_key: str,
        chunk_queue: queue_mod.Queue,
        metadata: Optional[dict] = None,
    ) -> Optional[str]:
        """Stream chunks from queue to MinIO. Skips if object already exists.

        Reads from chunk_queue until a None sentinel is received.
        Blocks the calling thread until upload completes.
        """
        if self.exists(object_key):
            # Drain queue to unblock the producer
            while True:
                try:
                    if chunk_queue.get(timeout=300) is None:
                        break
                except queue_mod.Empty:
                    break
            logger.debug(f"File cache hit, skipped upload: {object_key}")
            return None

        metadata = dict(metadata) if metadata else {}
        content_type = metadata.pop("content_type", "application/octet-stream")
        stream = _QueueStream(chunk_queue)
        self.client.put_object(
            self.bucket,
            object_key,
            stream,
            length=-1,
            part_size=10 * 1024 * 1024,
            content_type=content_type,
            metadata=metadata,
        )
        logger.info(f"Streamed file to MinIO: {object_key}")
        return object_key

    def retrieve_file(self, object_key: str) -> Optional[bytes]:
        """Retrieve a file from MinIO. Returns None if not found."""
        try:
            response = self.client.get_object(self.bucket, object_key)
            data = response.read()
            response.close()
            response.release_conn()
            return data
        except S3Error as e:
            if e.code == "NoSuchKey":
                return None
            raise

    def exists(self, object_key: str) -> bool:
        """Check if an object exists in MinIO."""
        try:
            self.client.stat_object(self.bucket, object_key)
            return True
        except S3Error:
            return False
