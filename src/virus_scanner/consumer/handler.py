import json
import logging
import os
import time

import redis

from .coordinator import ClusterCoordinator
from .engine import ScannerEngine
from .settings import Settings


class VirusScanHandler:
    def __init__(
        self,
        redis_client: redis.Redis,
        settings: Settings,
        engine: ScannerEngine,
        coordinator: ClusterCoordinator,
        stream_factory,
        path_factory,
        body_factory,
    ):
        self.redis = redis_client
        self.settings = settings
        self.engine = engine
        self.coordinator = coordinator
        self.stream_factory = stream_factory
        self.path_factory = path_factory
        self.body_factory = body_factory
        self.logger = logging.getLogger(__name__)

    def _get_free_memory_mb(self) -> float:
        """Get available memory in MB"""
        if not self.settings.enable_memory_check:
            return float("inf")
        try:
            import psutil

            vm = psutil.virtual_memory()
            return vm.available / (1024 * 1024)
        except ImportError:
            return float("inf")

    def run(self):
        """Main loop: coordinates, polls, and processes."""
        self.logger.info(
            f"Starting Virus Scanner Worker (Redis: {self.settings.redis_host}, Queues: {self.settings.queues})"
        )

        while True:
            try:
                # 1. Cluster Coordination (Heartbeat & Reload check)
                self.coordinator.heartbeat()
                self.coordinator.handle_sequential_update()

                # 2. Queue Polling (Wait for task)
                # We check ClamAV health implicitly via the Engine later,
                # but a quick ping here prevents polling if ClamAV is totally down.

                # Poll queues (Priority first)
                result = self.redis.blpop(self.settings.queues, timeout=2)
                if not result:
                    continue

                queue_name, task_data = result
                self._process_task(task_data, queue_name)

            except Exception as e:
                self.logger.error(f"Handler loop error: {e}")
                time.sleep(2)

    def _process_task(self, task_data: str, queue_name: str):
        """Orchestrates the lifecycle of a single scan task."""
        try:
            # Detect format (Legacy JSON vs New Pipe-separated)
            if task_data.startswith("{"):
                self._process_legacy_task(task_data, queue_name)
            else:
                self._process_stream_task(task_data, queue_name)
        except Exception as e:
            self.logger.error(f"Failed to process task: {e}")

    def _process_stream_task(self, task_pipe: str, queue_name: str):
        """Handles the new highly-efficient pipe-separated task format."""
        # Format: task_id|mode|push_time|content
        parts = task_pipe.split("|", 3)
        if len(parts) < 4:
            self.logger.error(f"Invalid task format: {task_pipe}")
            return

        task_id, mode, push_time_str, content = parts
        push_time = int(push_time_str)

        # 1. Prepare Provider
        provider = None
        if mode == "PATH":
            file_path = os.path.join(self.settings.scan_mount, content)
            provider = self.path_factory(file_path=file_path)
        elif mode == "BODY":
            provider = self.body_factory(data=content.encode("latin1"))
        elif mode == "STREAM":
            provider = self.stream_factory(chunks_key=content)
        else:
            self.logger.error(f"Unknown mode: {mode}")
            return

        # 2. Execute Scan
        mem_before = self._get_free_memory_mb()
        start_time = time.time()

        try:
            is_virus, virus_name = self.engine.scan(provider)
        except Exception as e:
            self.redis.rpush(
                f"result:{task_id}", json.dumps({"status": "ERROR", "message": str(e)})
            )
            return

        duration = time.time() - start_time
        mem_after = self._get_free_memory_mb()
        mem_delta = mem_before - mem_after if mem_before != float("inf") else 0
        total_tat_ms = (time.time_ns() - push_time) / 1e6

        self.logger.info(
            f"Scan Done {task_id}: {duration * 1000:.1f}ms, Virus={virus_name if is_virus else 'None'}, MemDelta={mem_delta:.0f}MB"
        )

        # 3. Report Results
        result_payload = {
            "status": "INFECTED" if is_virus else "CLEAN",
            "virus": virus_name if is_virus else None,
            "data_key": provider.get_data_key() if not is_virus else None,
            "metrics": {"scan_ms": duration * 1000, "total_tat_ms": total_tat_ms},
        }
        self.redis.rpush(f"result:{task_id}", json.dumps(result_payload))
        self.redis.expire(f"result:{task_id}", 3600)

    def _process_legacy_task(self, task_json: str, queue_name: str):
        """Minimal support for old JSON format using the new Engine."""
        task = json.loads(task_json)
        task_id = task.get("id", "unknown")
        file_path = task.get("file_path")

        if file_path:
            provider = self.path_factory(
                file_path=file_path, delete_after=False
            )  # Legacy might expect file to stay
            is_virus, _ = self.engine.scan(provider)
            self.logger.info(f"Legacy task {task_id} result: {is_virus}")
