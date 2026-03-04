import asyncio
import hashlib
import logging
import queue as queue_mod
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Optional

from ...virusscan.common.queue.provider import StateStoreProvider
from ..domain.policy import BypassPolicy

logger = logging.getLogger(__name__)


class IntelligentCacheService:
    """
    Application service that orchestrates the bypass logic and cache lookups asynchronously.
    """

    _INFECTED_TTL = 180 * 24 * 3600  # 180 days

    _BINARY_CONTENT_TYPES = frozenset({
        "application/octet-stream",
        "application/zip",
        "application/gzip",
        "application/x-gzip",
        "application/x-tar",
        "application/x-bzip2",
        "application/x-xz",
        "application/x-7z-compressed",
        "application/x-rar-compressed",
        "application/vnd.rar",
        "application/x-debian-package",
        "application/x-rpm",
        "application/x-msdownload",
        "application/x-msi",
        "application/java-archive",
        "application/x-executable",
        "application/x-sharedlib",
        "application/vnd.android.package-archive",
        "application/wasm",
    })

    _ARCHIVE_EXTENSIONS = frozenset({
        ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".xz",
        ".deb", ".rpm", ".exe", ".msi", ".dmg", ".pkg",
        ".jar", ".war", ".ear",
        ".apk", ".aab",
        ".whl", ".egg",
        ".iso", ".img",
        ".so", ".dll", ".dylib",
        ".wasm",
    })

    _executor = ThreadPoolExecutor(max_workers=2)

    def _get_cache_key(self, uri: str) -> str:
        key_hash = hashlib.sha256(uri.encode()).hexdigest()
        return f"aether:cache:uri:{key_hash}"

    def _get_infected_key(self, uri: str) -> str:
        key_hash = hashlib.sha256(uri.encode()).hexdigest()
        return f"aether:infected:uri:{key_hash}"

    def _make_object_key(self, path: str) -> str:
        """Generate URL-based object key (shared across tenants)."""
        clean_path = path.split("?")[0].split("#")[0]
        filename = PurePosixPath(clean_path).name or "unknown"
        url_hash = hashlib.sha256(clean_path.encode()).hexdigest()
        return f"files/{url_hash[:2]}/{url_hash}/{filename}"

    def __init__(
        self,
        provider: StateStoreProvider,
        policy: BypassPolicy,
        file_store=None,
    ):
        self.provider = provider
        self.policy = policy
        self.file_store = file_store

    async def get_notable_type(self, uri: str) -> str | None:
        """
        Identifies if the URI belongs to a notable category (e.g., 'docker').
        """
        # Policy checks are currently sync, but we make this async for future-proofing
        return self.policy.get_notable_type(uri)

    async def check_priority(self, plan: str) -> str:
        """
        Determines scan priority based on the user's plan.
        """
        if plan in ["premium", "enterprise", "business"]:
            return "high"
        return "normal"

    async def check_cache(self, uri: str) -> bool:
        """
        Determines if the URI should skip scanning due to policy or cache (Async).
        """
        # 1. Domain Policy Check
        if self.policy.should_bypass(uri):
            logger.debug(f"BYPASS: Policy match for {uri}")
            return True

        # 2. Redis Cache Lookup (Async)
        cache_key = self._get_cache_key(uri)
        return await self.provider.exists(cache_key)

    async def check_infected(self, uri: str) -> str | None:
        key = self._get_infected_key(uri)
        return await self.provider.get(key)

    async def store_infected(self, uri: str, virus_name: str) -> None:
        key = self._get_infected_key(uri)
        await self.provider.set(key, virus_name, ex=self._INFECTED_TTL)
        logger.warning(f"INFECTED cached ({virus_name}): {uri} [TTL=180d]")

    async def store_cache(self, uri: str, ttl: int = 3600):
        cache_key = self._get_cache_key(uri)
        await self.provider.set(cache_key, "1", ex=ttl)

    # --- File Storage ---

    def should_store_file(self, path: str, content_type: Optional[str] = None) -> bool:
        """Determine if the file should be stored based on content-type or path extension."""
        if content_type:
            ct = content_type.split(";")[0].strip().lower()
            if ct in self._BINARY_CONTENT_TYPES:
                return True

        clean_path = path.split("?")[0].split("#")[0]
        name = PurePosixPath(clean_path).name.lower()

        for ext in self._ARCHIVE_EXTENSIONS:
            if name.endswith(ext):
                return True

        return False

    def start_streaming_upload(
        self,
        task_id: str,
        tenant_id: str,
        path: str,
        content_type: Optional[str],
    ) -> Optional[queue_mod.Queue]:
        """Start a streaming file upload to MinIO in a background thread.

        Returns a queue.Queue to feed body chunks into, or None if file_store
        is not configured. Put None into the queue to signal end of stream.

        The upload thread handles exists-check internally — if the file is
        already cached, it drains the queue and returns without uploading.
        """
        if not self.file_store:
            return None

        object_key = self._make_object_key(path)
        chunk_queue = queue_mod.Queue()
        metadata = {
            "content_type": content_type or "application/octet-stream",
            "original_url": path[:512],
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_id": tenant_id,
            "task_id": task_id,
        }

        self._executor.submit(
            self._streaming_upload_worker, object_key, chunk_queue, metadata,
        )
        return chunk_queue

    def _streaming_upload_worker(self, object_key, chunk_queue, metadata):
        """Thread pool worker: stream chunks from queue to MinIO."""
        try:
            self.file_store.store_file_streamed(object_key, chunk_queue, metadata)
        except Exception as e:
            logger.warning(f"Streaming upload failed for {object_key}: {e}")
            try:
                while True:
                    if chunk_queue.get(timeout=60) is None:
                        break
            except Exception:
                pass

    async def retrieve_file(self, object_key: str) -> Optional[bytes]:
        """Retrieve a stored file from MinIO via executor (non-blocking)."""
        if not self.file_store:
            return None
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            self.file_store.retrieve_file,
            object_key,
        )
