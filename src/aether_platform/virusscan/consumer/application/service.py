import json
import logging
import time
from typing import Any, Callable

from dependency_injector.wiring import Provide, inject

from aether_platform.virusscan.common.queue.provider import QueueProvider
from aether_platform.virusscan.consumer.infrastructure.engine_client import \
    ScannerEngineClient
from aether_platform.virusscan.consumer.settings import Settings


class ScannerTaskService:
    """
    Application service that processes individual virus scan tasks.
    Coordinates downloading the file, executing the scan, and reporting results.
    """

    def _get_free_memory_mb(self) -> float:
        """Internal helper to calculate available system memory in MB."""
        if not self.config.enable_memory_check:
            return float("inf")
        try:
            import psutil

            vm = psutil.virtual_memory()
            return vm.available / (1024 * 1024)
        except ImportError:
            return float("inf")

    def _report_result(self, task_id: str, result_payload: dict):
        """Internal helper to persist scan results to the queue provider."""
        result_json = json.dumps(result_payload).encode("utf-8")
        result_key = f"result:{task_id}"
        self.provider.push(result_key, result_json)

    def _notify_console(self, tenant_id: str, virus_name: str, task_id: str):
        """Internal helper to notify the management console of an infection."""
        try:
            import os

            import requests

            console_url = os.environ.get(
                "CONSOLE_API_URL", "http://aether-console:3000"
            )
            requests.post(
                f"{console_url}/api/webhooks/virus-scan",
                json={
                    "tenant_id": tenant_id,
                    "virus_name": virus_name,
                    "task_id": task_id,
                    "status": "INFECTED",
                },
                timeout=5,
            )
        except Exception as e:
            self.logger.error(f"Failed to notify console: {e}")

    async def _process_stream_task(self, task_pipe: str, queue_name: str):
        """Internal helper to process a task and report results back to the producer."""
        # Format: task_id|mode|push_time|content|tenant_id
        parts = task_pipe.split("|", 4)
        if len(parts) < 4:
            self.logger.error(f"Invalid task format: {task_pipe}")
            return

        task_id = parts[0]
        # mode = parts[1] (unused)
        push_time = int(parts[2])
        content = parts[3]
        tenant_id = parts[4] if len(parts) > 4 else "unknown"

        # 1. Prepare Provider
        try:
            provider = self.provider_factory("STREAM", chunks_key=content)
        except Exception as e:
            self.logger.error(f"Failed to create STREAM provider for {task_id}: {e}")
            return

        # 2. Execute Scan
        mem_before = self._get_free_memory_mb()
        start_time = time.time()

        try:
            is_virus, virus_name = self.engine.scan(provider)
        except Exception as e:
            error_payload = {"status": "ERROR", "message": str(e)}
            self._report_result(task_id, error_payload)
            return

        duration = time.time() - start_time
        mem_after = self._get_free_memory_mb()
        mem_delta = mem_before - mem_after if mem_before != float("inf") else 0
        total_tat_ms = (time.time_ns() - push_time) / 1e6

        self.logger.info(
            f"Scan Done {task_id}: {duration * 1000:.1f}ms, Virus={virus_name if is_virus else 'None'}, MemDelta={mem_delta:.0f}MB, Tenant={tenant_id}"
        )

        # 3. Report Results
        result_payload = {
            "status": "INFECTED" if is_virus else "CLEAN",
            "virus": virus_name if is_virus else None,
            "data_key": provider.get_data_key() if not is_virus else None,
            "metrics": {"scan_ms": duration * 1000, "total_tat_ms": total_tat_ms},
            "tenant_id": tenant_id,
        }
        self._report_result(task_id, result_payload)

        # 4. Notify Console if infected
        if is_virus:
            self._notify_console(tenant_id, virus_name, task_id)

        # 5. Record Metrics
        try:
            tat_key = (
                "tat_priority_last" if "priority" in queue_name else "tat_normal_last"
            )
            self.provider.set(tat_key, str(total_tat_ms))
        except Exception as e:
            self.logger.warning(f"Failed to record metrics: {e}")

    @inject
    def __init__(
        self,
        queue_provider: QueueProvider = Provide["queue_provider"],
        settings: Settings = Provide["settings"],
        engine: ScannerEngineClient = Provide["engine"],
        provider_factory: Callable[..., Any] = Provide["data_provider"],
    ):
        """
        Initializes the task service.

        Args:
            queue_provider: Abstraction over the transport/storage backend.
            settings: Consumer configuration.
            engine: ClamAV engine client.
            provider_factory: Factory for data ingestion strategies.
        """
        self.provider = queue_provider
        self.settings = settings
        self.engine = engine
        self.provider_factory = provider_factory
        self.logger = logging.getLogger(__name__)

    async def process_task(self, task_data: str, queue_name: str):
        """
        Orchestrates the lifecycle of a single scan task.

        Args:
            task_data: The raw pipe-separated task string.
            queue_name: The name of the queue the task was polled from.
        """
        try:
            await self._process_stream_task(task_data, queue_name)
        except Exception as e:
            self.logger.error(f"Failed to process task: {e}")
