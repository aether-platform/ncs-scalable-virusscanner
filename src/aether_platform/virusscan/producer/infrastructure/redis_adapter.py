import json
import logging
from typing import Optional

from dependency_injector.wiring import Provide, inject

from aether_platform.virusscan.common.queue.provider import QueueProvider
from aether_platform.virusscan.producer.containers import ProducerContainer

logger = logging.getLogger(__name__)


class RedisScanAdapter:
    """
    Infrastructure component acting as an Anti-Corruption Layer (ACL) for
    queue communication. Balanced for asynchronous operations.
    """

    @inject
    def __init__(
        self,
        queue_provider: QueueProvider = Provide[ProducerContainer.queue_provider],
    ):
        """
        Initializes the adapter.

        Args:
            queue_provider: An abstraction over the PubSub/Key-Value backend.
        """
        self.provider = queue_provider

    def _get_result_key(self, task_id: str) -> str:
        """Internal helper to generate the result channel key."""
        return f"result:{task_id}"

    def _get_metric_key(self, task_id: str) -> str:
        """Internal helper to generate the metrics storage key."""
        return f"metrics:ingest:{task_id}"

    async def enqueue_task(
        self,
        task_id: str,
        mode: str,
        start_time: int,
        tenant_id: str,
        is_priority: bool,
    ):
        """
        Pushes a new scan task as JSON job metadata into Redis.

        Args:
            task_id: Unique identifier for the scan task (Stream ID).
            mode: Data transfer mode (e.g., 'STREAM').
            start_time: Task creation timestamp in nanoseconds.
            tenant_id: Identifier for the user/tenant.
            is_priority: True to use the high-priority queue.
        """
        queue_name = "scan_priority" if is_priority else "scan_normal"

        # New JSON metadata format: { "stream_id": "...", "priority": "...", "enqueued_at": ... }
        job_metadata = {
            "stream_id": task_id,
            "priority": "high" if is_priority else "low",
            "enqueued_at": start_time
            / 1e9,  # Convert to seconds for consistency with time.time()
            "tenant_id": tenant_id,
            "mode": mode,
        }

        payload = json.dumps(job_metadata)
        await self.provider.push(queue_name, payload)

    async def record_metrics(self, task_id: str, duration_ms: float):
        """
        Stores ingestion performance metrics asynchronously.
        """
        try:
            await self.provider.set(
                self._get_metric_key(task_id), str(duration_ms), ex=3600
            )
        except Exception as e:
            logger.warning(f"Failed to record metrics for {task_id}: {e}")

    async def wait_for_ack(self, task_id: str, timeout: int = 300) -> bool:
        """
        Blocks asynchronously until a handshake ACK is received for the given task.
        """
        ack_key = f"ack:{task_id}"
        try:
            res = await self.provider.pop([ack_key], timeout=timeout)
            return bool(res)
        except Exception as e:
            logger.error(f"Error while waiting for ACK {task_id}: {e}")
            return False

    async def get_last_tat(self, is_priority: bool) -> float:
        """
        Retrieves the last recorded TAT (in seconds) for the given priority.
        """
        tat_key = "tat_high_last" if is_priority else "tat_normal_last"
        try:
            val = await self.provider.get(tat_key)
            return float(val) / 1000.0 if val else 0.0
        except Exception:
            return 0.0

    async def wait_for_result(
        self, task_id: str, timeout: int = 300
    ) -> Optional[bytes]:
        """
        Blocks asynchronously until a scan result is available for the given task.
        """
        try:
            res = await self.provider.pop(
                [self._get_result_key(task_id)], timeout=timeout
            )
            if res:
                return res[1]
            return None
        except Exception as e:
            logger.error(f"Error while waiting for result {task_id}: {e}")
            raise
