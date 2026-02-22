import json
import logging
import time
import uuid
from typing import Any, Dict, Tuple

from dependency_injector import providers
from dependency_injector.wiring import Provide, inject

from aether_platform.virusscan.producer.containers import ProducerContainer
from aether_platform.virusscan.producer.domain.models import (ScanResult,
                                                              ScanStatus)
from aether_platform.virusscan.producer.infrastructure.redis_adapter import \
    RedisScanAdapter

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """
    Application service that orchestrates the workflow of a single virus scan.
    Manages session lifecycle, delegates blocking calls to the adapter, and
    interfaces with storage providers.
    """

    _start_times: Dict[str, Tuple[int, str]] = {}

    @inject
    def __init__(
        self,
        redis_adapter: RedisScanAdapter = Provide[ProducerContainer.redis_adapter],
        provider_factory: providers.FactoryAggregate = Provide[
            ProducerContainer.data_provider
        ],
    ):
        """
        Initializes the orchestrator.

        Args:
            redis_adapter: Infrastructure adapter for queue operations.
            provider_factory: Factory to create DataProvider strategies.
        """
        self.adapter = redis_adapter
        self.provider_factory = provider_factory
        self._start_times = {}  # task_id -> (start_ns, tenant_id)

    def _get_start_data(self, task_id: str) -> Tuple[int, str] | None:
        """Internal helper to retrieve session start data."""
        return self._start_times.get(task_id)

    def prepare_session(
        self, is_priority: bool = False, tenant_id: str = "unknown"
    ) -> Tuple[str, Any]:
        """
        Initializes a new scan session and prepares the data provider.

        Args:
            is_priority: Initial priority hint.
            tenant_id: Tenant identifier.

        Returns:
            A tuple of (task_id, provider).
        """
        task_id = str(uuid.uuid4())
        self._start_times[task_id] = (time.time_ns(), tenant_id)

        provider = self.provider_factory("STREAM", chunks_key=task_id)
        return task_id, provider

    def start_scan(
        self, task_id: str, is_priority: bool = False, tenant_id: str = "unknown"
    ):
        """
        Emits the scan task to the queue for asynchronous processing.

        Args:
            task_id: Task identifier.
            is_priority: Final priority decision.
            tenant_id: Tenant identifier.
        """
        data = self._get_start_data(task_id)
        start_time = data[0] if data else time.time_ns()
        self.adapter.enqueue_task(task_id, "STREAM", start_time, tenant_id, is_priority)

    def finalize_ingest(self, task_id: str):
        """
        Records the completion of the data ingestion phase.

        Args:
            task_id: Task identifier.
        """
        data = self._get_start_data(task_id)
        if data:
            start_time, _ = data
            duration_ms = (time.time_ns() - start_time) / 1e6
            self.adapter.record_metrics(task_id, duration_ms)

    def get_result(self, task_id: str, timeout: int = 30) -> ScanResult:
        """
        Waits for and retrieves the scan result.

        Args:
            task_id: Task identifier.
            timeout: Maximum wait time in seconds.

        Returns:
            A ScanResult domain object.
        """
        try:
            raw_res = self.adapter.wait_for_result(task_id, timeout)
            self._start_times.pop(task_id, None)

            if not raw_res:
                return ScanResult(
                    task_id=task_id, status=ScanStatus.ERROR, detail="Timeout"
                )

            data = json.loads(raw_res.decode("utf-8"))
            status_str = data.get("status", "ERROR")

            return ScanResult(
                task_id=task_id,
                status=ScanStatus[status_str]
                if status_str in ScanStatus.__members__
                else ScanStatus.ERROR,
                virus_name=data.get("virus"),
                detail=data.get("detail"),
            )
        except Exception as e:
            self._start_times.pop(task_id, None)
            return ScanResult(task_id=task_id, status=ScanStatus.ERROR, detail=str(e))
