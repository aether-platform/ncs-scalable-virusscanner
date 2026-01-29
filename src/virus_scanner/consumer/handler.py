import logging
import time

import redis

from .coordinator import ClusterCoordinator
from .service import ScannerTaskService
from .settings import Settings


class VirusScanHandler:
    """
    Main worker loop for the Virus Scanner Consumer.
    Handles cluster coordination and polling tasks from Redis.
    """

    def __init__(
        self,
        redis_client: redis.Redis,
        settings: Settings,
        coordinator: ClusterCoordinator,
        task_service: ScannerTaskService,
    ):
        self.redis = redis_client
        self.settings = settings
        self.coordinator = coordinator
        self.task_service = task_service
        self.logger = logging.getLogger(__name__)

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
                result = self.redis.blpop(self.settings.queues, timeout=2)
                if not result:
                    continue

                queue_name_raw, task_data_raw = result
                queue_name = queue_name_raw.decode("utf-8")
                task_data = task_data_raw.decode("utf-8")

                # 3. Delegate to Task Service
                self.task_service.process_task(task_data, queue_name)

            except Exception as e:
                self.logger.error(f"Handler loop error: {e}")
                time.sleep(2)
