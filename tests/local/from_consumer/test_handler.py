import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
import redis.asyncio as redis

from aether_platform.virusscan.consumer.interfaces.worker.handler import (
    VirusScanHandler,
)
from aether_platform.virusscan.consumer.settings import Settings


@pytest.fixture
def mock_redis():
    return AsyncMock(spec=redis.Redis)


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
def mock_queue_provider():
    return AsyncMock()


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

    class StopIter(BaseException):
        pass

    # Mock provider.pop to return a task and then raise an exception to break the loop for testing
    job_metadata = {
        "stream_id": "stream-123",
        "priority": "high",
        "enqueued_at": time.time() - 10,
    }
    task_data_json = json.dumps(job_metadata)

    # mock_queue_provider.pop is an AsyncMock
    mock_queue_provider.pop.side_effect = [
        ("scan_priority", task_data_json.encode("utf-8")),
        StopIter(),
    ]

    try:
        await handler.run()
    except (StopIter, KeyboardInterrupt):
        pass

    # Verify coordinator methods called (sync)
    mock_coordinator.heartbeat.assert_called()
    mock_coordinator.handle_sequential_update.assert_called()

    # Verify task service called (async) with start_process_time
    mock_task_service.process_task.assert_called()
    call_args = mock_task_service.process_task.call_args[0]
    assert call_args[0] == task_data_json
    assert call_args[1] == "scan_priority"
    assert isinstance(call_args[2], float)  # start_process_time
