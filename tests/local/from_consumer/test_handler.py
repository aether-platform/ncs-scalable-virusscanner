from unittest.mock import MagicMock

import pytest
import redis

from virus_scanner.consumer.handler import VirusScanHandler
from virus_scanner.consumer.settings import Settings


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


@pytest.fixture
def mock_coordinator():
    return MagicMock()


@pytest.fixture
def mock_task_service():
    return MagicMock()


def test_handler_loop_iteration(
    mock_redis, settings, mock_coordinator, mock_task_service
):
    """Test one iteration of the handler loop"""
    handler = VirusScanHandler(
        redis_client=mock_redis,
        settings=settings,
        coordinator=mock_coordinator,
        task_service=mock_task_service,
    )

    # Mock Redis blpop to return a task and then raise an exception to break the loop for testing
    task_data = "task-123|STREAM|123456|chunks-key"
    mock_redis.blpop.side_effect = [
        (b"scan_normal", task_data.encode("utf-8")),
        KeyboardInterrupt("Stop loop for testing"),
    ]

    try:
        handler.run()
    except KeyboardInterrupt:
        pass

    # Verify coordinator methods called
    mock_coordinator.heartbeat.assert_called()
    mock_coordinator.handle_sequential_update.assert_called()

    # Verify task service called
    mock_task_service.process_task.assert_called_once_with(task_data, "scan_normal")
