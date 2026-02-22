import logging
from typing import Optional

from dependency_injector.wiring import Provide, inject

from aether_platform.virusscan.common.queue.provider import QueueProvider
from aether_platform.virusscan.producer.containers import ProducerContainer

logger = logging.getLogger(__name__)


class RedisScanAdapter:
    """
    Infrastructure component acting as an Anti-Corruption Layer (ACL) for
    queue communication. Decouples the application orchestration from raw Redis commands.
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

    def enqueue_task(
        self,
        task_id: str,
        mode: str,
        start_time: int,
        tenant_id: str,
        is_priority: bool,
    ):
        """
        Pushes a new scan task into the priority or normal queue.

        Args:
            task_id: Unique identifier for the scan task.
            mode: Data transfer mode (e.g., 'STREAM').
            start_time: Task creation timestamp in nanoseconds.
            tenant_id: Identifier for the user/tenant.
            is_priority: True to use the high-priority queue.
        """
        queue_name = "scan_priority" if is_priority else "scan_normal"
        # Payload format: taskID|MODE|TIMESTAMP|CONTENT(taskID)|TENANT_ID
        payload = f"{task_id}|{mode}|{start_time}|{task_id}|{tenant_id}"
        self.provider.push(queue_name, payload)

    def record_metrics(self, task_id: str, duration_ms: float):
        """
        Stores ingestion performance metrics.

        Args:
            task_id: Task identifier.
            duration_ms: Total ingestion time in milliseconds.
        """
        try:
            self.provider.set(self._get_metric_key(task_id), str(duration_ms), ex=3600)
        except Exception as e:
            logger.warning(f"Failed to record metrics for {task_id}: {e}")

    def wait_for_result(self, task_id: str, timeout: int = 30) -> Optional[bytes]:
        """
        Blocks until a scan result is available for the given task.

        Args:
            task_id: Task identifier.
            timeout: Maximum wait time in seconds.

        Returns:
            The raw JSON result bytes, or None on timeout.
        """
        try:
            res = self.provider.pop([self._get_result_key(task_id)], timeout=timeout)
            if res:
                return res[1]
            return None
        except Exception as e:
            logger.error(f"Error while waiting for result {task_id}: {e}")
            raise
