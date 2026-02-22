import logging
import time

from dependency_injector.wiring import Provide, inject

from aether_platform.virusscan.common.queue.provider import QueueProvider
from aether_platform.virusscan.consumer.application.service import ScannerTaskService
from aether_platform.virusscan.consumer.infrastructure.coordinator import (
    ClusterCoordinator,
)
from aether_platform.virusscan.consumer.settings import Settings


class VirusScanHandler:
    """
    Main worker loop for the Virus Scanner Consumer.
    Translates transport-level events (Queue/Redis) into application actions.
    """

    @inject
    def __init__(
        self,
        queue_provider: QueueProvider = Provide["queue_provider"],
        settings: Settings = Provide["settings"],
        coordinator: ClusterCoordinator = Provide["coordinator"],
        task_service: ScannerTaskService = Provide["task_service"],
    ):
        """
        Initializes the handler worker.

        Args:
            queue_provider: Abstraction over the message queue backend.
            settings: Consumer configuration.
            coordinator: Cluster coordination manager.
            task_service: Application service for task execution.
        """
        self.provider = queue_provider
        self.settings = settings
        self.coordinator = coordinator
        self.task_service = task_service
        self.logger = logging.getLogger(__name__)

    async def run(self):
        """
        The main worker execution loop.
        Continuously heartbeats and polls for new scan tasks.
        """
        self.logger.info(
            f"Starting Virus Scanner Worker (Backend: {type(self.provider).__name__}, Queues: {self.settings.queues})"
        )

        while True:
            try:
                # 1. Cluster Coordination (Heartbeat & Reload check)
                self.coordinator.heartbeat()
                self.coordinator.handle_sequential_update()
                # TODO: 優先キューと、通常キューの考慮が足りない。5タスク走らせて、4つは優先、1つは通常。といった形や、4つは優先だが、優先タスクが無い場合、通常キューを実施といった考慮が必要。
                # 2. Queue Polling (Wait for task)
                result = self.provider.pop(self.settings.queues, timeout=2)
                if not result:
                    continue

                queue_name, task_data_raw = result
                task_data = task_data_raw.decode("utf-8")

                # 3. Delegate to Application Service
                await self.task_service.process_task(task_data, queue_name)

            except Exception as e:
                self.logger.error(f"Handler loop error: {e}")
                time.sleep(2)
