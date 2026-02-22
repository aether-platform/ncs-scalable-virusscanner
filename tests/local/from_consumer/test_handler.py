from unittest.mock import MagicMock

import pytest
import redis

from aether_platform.virusscan.consumer.interfaces.worker.handler import (
    VirusScanHandler,
)
from aether_platform.virusscan.consumer.settings import Settings


@pytest.fixture
def mock_redis():
    return MagicMock(spec=redis.Redis)


@pytest.fixture
def settings():
    return Settings(
        redis_host="localhost",
        redis_port=6379,
        clamd_url="tcp://localhost:3310",
        queues=["scan_priority", "scan_normal"],
        scan_mount="/tmp/virusscan",
        enable_memory_check=False,
    )


from unittest.mock import AsyncMock


@pytest.fixture
def mock_queue_provider():
    return MagicMock()


@pytest.fixture
def mock_coordinator():
    return MagicMock()


@pytest.fixture
def mock_task_service():
    return AsyncMock()


@pytest.mark.asyncio
async def test_handler_loop_iteration(
    mock_queue_provider, settings, mock_coordinator, mock_task_service
):
    """Test one iteration of the handler loop"""
    handler = VirusScanHandler(
        queue_provider=mock_queue_provider,
        settings=settings,
        coordinator=mock_coordinator,
        task_service=mock_task_service,
    )

    # Mock provider.pop to return a task and then raise an exception to break the loop for testing
    task_data = "task-123|STREAM|123456|chunks-key"
    mock_queue_provider.pop.side_effect = [
        ("scan_normal", task_data.encode("utf-8")),
        KeyboardInterrupt("Stop loop for testing"),
    ]

    try:
        await handler.run()
    except KeyboardInterrupt:
        pass

    # Verify coordinator methods called
    mock_coordinator.heartbeat.assert_called()
    mock_coordinator.handle_sequential_update.assert_called()

    # Verify task service called
    mock_task_service.process_task.assert_called_once_with(task_data, "scan_normal")
