import asyncio
import json
import time
from unittest.mock import AsyncMock

import pytest
import redis.asyncio as redis

from aether_platform.virusscan.consumer.interfaces.worker.handler import \
    VirusScanHandler
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
    return AsyncMock()


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

    # Mock provider.pop to return a job and then raise StopIter to break the loop
    job_metadata = {
        "stream_id": "stream-123",
        "priority": "high",
        "enqueued_at": time.time() - 10,
    }
    task_data_json = json.dumps(job_metadata)

    # Use a side_effect function to handle concurrent workers
    pop_calls = 0

    async def side_effect(*args, **kwargs):
        nonlocal pop_calls
        pop_calls += 1
        if pop_calls == 1:
            return ("scan_priority", task_data_json.encode("utf-8"))
        elif pop_calls == 2:
            raise StopIter()
        else:
            # Other workers just wait or return None
            await asyncio.sleep(0.1)
            return None

    mock_queue_provider.pop.side_effect = side_effect

    try:
        await handler.run()
    except (StopIter, KeyboardInterrupt):
        pass

    # Verify coordinator methods called
    mock_coordinator.heartbeat.assert_called()
    mock_coordinator.handle_sequential_update.assert_called()

    # Verify task service called
    mock_task_service.process_task.assert_called()

    # Check arguments: (task_data, queue_name, start_process_time=...)
    # AsyncMock keeps track of call in call_args which has .args and .kwargs
    last_call = mock_task_service.process_task.call_args
    assert last_call.args[0] == task_data_json
    assert last_call.args[1] == "scan_priority"
    assert "start_process_time" in last_call.kwargs
    assert isinstance(last_call.kwargs["start_process_time"], float)
