import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from aether_platform.virusscan.consumer.application.service import \
    ScannerTaskService
from aether_platform.virusscan.consumer.settings import Settings


@pytest.fixture
def mock_queue_provider():
    return AsyncMock()


@pytest.fixture
def mock_state_store():
    return AsyncMock()


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
def mock_engine():
    return AsyncMock()


@pytest.fixture
def mock_provider_factory():
    return MagicMock()


@pytest.fixture
def task_service(
    mock_queue_provider, mock_state_store, settings, mock_engine, mock_provider_factory
):
    return ScannerTaskService(
        queue_provider=mock_queue_provider,
        state_store_provider=mock_state_store,
        settings=settings,
        engine=mock_engine,
        provider_factory=mock_provider_factory,
    )


@pytest.mark.asyncio
async def test_process_task_clean(
    task_service, mock_queue_provider, mock_engine, mock_provider_factory
):
    """Test processing a task that is clean"""
    task_id = "task-123"
    job_metadata = {
        "stream_id": task_id,
        "enqueued_at": time.time() - 10,
        "mode": "STREAM",
        "tenant_id": "test-tenant",
        "client_ip": "127.0.0.1",
    }
    task_data = json.dumps(job_metadata)

    # Mock provider
    mock_provider = MagicMock()
    mock_provider_factory.return_value = mock_provider

    # Mock engine
    mock_engine.scan.return_value = (False, None)  # Clean

    await task_service.process_task(
        task_data, "scan_normal", start_process_time=time.time()
    )

    # Verify engine called
    mock_engine.scan.assert_called_once_with(mock_provider)
    mock_provider_factory.assert_called_with("STREAM", chunks_key=task_id)

    # Verify result pushed to Queue
    mock_queue_provider.push.assert_called()
    # Check that a key like result:task-123 was pushed
    # The exact call order might vary, but we look for the result key
    calls = mock_queue_provider.push.call_args_list
    result_call = next(c for c in calls if c.args[0] == f"result:{task_id}")
    result_data = json.loads(result_call.args[1].decode("utf-8"))
    assert result_data["status"] == "CLEAN"


@pytest.mark.asyncio
async def test_process_task_infected(
    task_service, mock_queue_provider, mock_engine, mock_provider_factory
):
    """Test processing a task that is infected"""
    task_id = "task-456"
    job_metadata = {
        "stream_id": task_id,
        "enqueued_at": time.time() - 10,
        "mode": "STREAM",
        "tenant_id": "test-tenant",
        "client_ip": "127.0.0.1",
    }
    task_data = json.dumps(job_metadata)

    # Mock provider
    mock_provider = MagicMock()
    mock_provider_factory.return_value = mock_provider

    # Mock engine
    mock_engine.scan.return_value = (True, "Eicar-Test-Signature")  # Infected

    await task_service.process_task(
        task_data, "scan_normal", start_process_time=time.time()
    )

    # Verify result pushed to Queue
    mock_queue_provider.push.assert_called()
    calls = mock_queue_provider.push.call_args_list
    result_call = next(c for c in calls if c.args[0] == f"result:{task_id}")
    result_data = json.loads(result_call.args[1].decode("utf-8"))
    assert result_data["status"] == "INFECTED"
    assert result_data["virus"] == "Eicar-Test-Signature"
