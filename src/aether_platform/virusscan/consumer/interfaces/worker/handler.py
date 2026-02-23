import asyncio
import logging
import time
from typing import Optional

from dependency_injector.wiring import Provide, inject

from aether_platform.virusscan.common.queue.provider import QueueProvider
from aether_platform.virusscan.consumer.application.service import \
    ScannerTaskService
from aether_platform.virusscan.consumer.infrastructure.coordinator import \
    ClusterCoordinator
from aether_platform.virusscan.consumer.settings import Settings

# TAT計測用メトリクス
# scanner_tat_seconds を application.service 側で処理するためここからは削除します


class VirusScanHandler:
    """
    Main worker loop for the Virus Scanner Consumer.
    Translates transport-level events (Queue/Redis) into application actions.
    Implements Worker Affinity: one worker handles all chunks of a stream.
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

    async def _worker_loop(
        self,
        name: str,
        primary_q: str,
        secondary_q: Optional[str] = None,
        shutdown_event: Optional[asyncio.Event] = None,
    ):
        """
        Individual worker loop that processes metadata jobs from common queues.
        """
        self.logger.info(
            f"Worker [{name}] started. Primary={primary_q}, Secondary={secondary_q}"
        )

        while True:
            # Check for shutdown signal
            if shutdown_event and shutdown_event.is_set():
                self.logger.info(f"Worker [{name}] shutting down gracefully...")
                break

            try:
                # Determine which queues to check.
                queues = [primary_q]
                if secondary_q:
                    queues.append(secondary_q)

                # Queue Polling (Async)
                result = await self.provider.pop(queues, timeout=2)
                if not result:
                    continue

                queue_name, task_data_raw = result
                task_data = task_data_raw.decode("utf-8")
                start_process_time = time.time()

                # Delegate to Application Service for Affinity processing
                await self.task_service.process_task(
                    task_data, queue_name, start_process_time=start_process_time
                )

            except (asyncio.CancelledError, KeyboardInterrupt):
                raise
            except Exception as e:
                self.logger.error(f"Worker [{name}] error: {e}")
                await asyncio.sleep(1)

    async def run(self, shutdown_event: Optional[asyncio.Event] = None):
        """
        The main worker execution manager.
        Starts the coordination loop and multiple concurrent worker loops (4:1 ratio).
        """
        self.logger.info(
            f"Starting Virus Scanner Consumer (Backend: {type(self.provider).__name__}, Queues: {self.settings.queues})"
        )

        # Identify priority and normal queues from settings
        priority_q = None
        normal_q = None
        for q in self.settings.queues:
            if "priority" in q:
                priority_q = q
            else:
                normal_q = q

        # Start Coordination Loop (Heartbeat and Reload checks)
        async def coordination_loop():
            while True:
                if shutdown_event and shutdown_event.is_set():
                    self.logger.info("Coordination loop shutting down gracefully...")
                    break
                try:
                    await self.coordinator.heartbeat()
                    await self.coordinator.handle_sequential_update()
                except Exception as e:
                    self.logger.error(f"Coordination loop error: {e}")
                await asyncio.sleep(30)  # Heartbeat interval

        tasks = [asyncio.create_task(coordination_loop())]

        # Start 4:1 Worker tasks
        if priority_q:
            # 4 Workers: Primary=Priority, Secondary=Normal (Help Normal if Priority is empty)
            for i in range(4):
                tasks.append(
                    asyncio.create_task(
                        self._worker_loop(
                            f"High-Staff-{i}", priority_q, normal_q, shutdown_event
                        )
                    )
                )

            # 1 Worker: Primary=Normal (Focused on Normal)
            if normal_q:
                tasks.append(
                    asyncio.create_task(
                        self._worker_loop(
                            "Low-Staff-0", normal_q, shutdown_event=shutdown_event
                        )
                    )
                )
        else:
            # Fallback for single queue setup
            for i in range(5):
                tasks.append(
                    asyncio.create_task(
                        self._worker_loop(
                            f"Worker-{i}",
                            self.settings.queues[0],
                            shutdown_event=shutdown_event,
                        )
                    )
                )

        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)

        for task in pending:
            task.cancel()

        # Re-raise any exceptions from the done tasks
        for task in done:
            if not task.cancelled() and task.exception():
                raise task.exception()
