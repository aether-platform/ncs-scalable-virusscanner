import time
import uuid
from typing import Any, Callable, Optional, Tuple

from .settings import ProducerSettings


class StreamScannerService:
    """
    High-level service to orchestrate virus scan task emission.
    It encapsulates the logic of choosing the best Provider and emitting to Redis.
    """

    def __init__(
        self,
        redis_client: Any,
        settings: ProducerSettings,
        provider_factory: Callable[..., Any],
    ):
        self.redis = redis_client
        self.settings = settings
        self.provider_factory = provider_factory
        self._start_times = {}  # task_id -> start_ns

    def prepare_scan(self, is_priority: bool = False) -> Tuple[str, Any]:
        """
        Initializes a new scan session and starts the timer.
        Returns (task_id, provider).
        """
        task_id = str(uuid.uuid4())
        self._start_times[task_id] = time.time_ns()

        # We default to STREAM mode for true real-time follower scanning
        provider = self.provider_factory("STREAM", chunks_key=task_id)
        return task_id, provider

    def emit_task(self, task_id: str, is_priority: bool = False):
        """Emits the task to the Redis queue using the internal start timer."""
        queue_name = "scan_priority" if is_priority else "scan_normal"
        start_time = self._start_times.get(task_id, time.time_ns())

        # Format: taskID|MODE|TIMESTAMP|CONTENT(chunks_key)
        self.redis.lpush(
            queue_name,
            f"{task_id}|STREAM|{start_time}|{task_id}",
        )

    def record_ingest_time(self, task_id: str):
        """Calculates and stores the ingest (upload) duration without popping the start timer."""
        start_time = self._start_times.get(task_id)
        if not start_time:
            return

        duration_ms = (time.time_ns() - start_time) / 1e6
        try:
            self.redis.set(f"metrics:ingest:{task_id}", str(duration_ms), ex=3600)
            self.redis.set("ingest_ms_last", str(duration_ms))
        except Exception:
            pass

    def wait_for_result(self, task_id: str, timeout: int = 30) -> Optional[bytes]:
        """Blocks until a result is available, records E2E TAT, and cleans up session."""
        try:
            res = self.redis.brpop(f"result:{task_id}", timeout=timeout)

            # Final E2E TAT measurement and cleanup
            start_time = self._start_times.pop(task_id, None)
            if res and start_time:
                e2e_duration_ms = (time.time_ns() - start_time) / 1e6
                self.redis.set("e2e_tat_ms_last", str(e2e_duration_ms))

            if res:
                return res[1]
            return None
        except Exception:
            self._start_times.pop(task_id, None)  # Ensure cleanup on error
            raise
