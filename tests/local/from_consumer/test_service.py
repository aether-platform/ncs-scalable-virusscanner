import json
import time
from unittest.mock import MagicMock

import pytest
import redis

from virus_scanner.consumer.service import ScannerTaskService
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
def mock_engine():
    return MagicMock()


@pytest.fixture
def mock_provider_factory():
    return MagicMock()


@pytest.fixture
def task_service(mock_redis, settings, mock_engine, mock_provider_factory):
    return ScannerTaskService(
        redis_client=mock_redis,
        settings=settings,
        engine=mock_engine,
        provider_factory=mock_provider_factory,
    )


def test_process_task_clean(
    task_service, mock_redis, mock_engine, mock_provider_factory
):
    """Test processing a task that is clean"""
    task_id = "task-123"
    push_time = int(time.time_ns())
    # Format: taskID|MODE|TIMESTAMP|CONTENT(chunks_key)
    task_data = f"{task_id}|STREAM|{push_time}|{task_id}"

    # Mock provider
    mock_provider = MagicMock()
    mock_provider.get_data_key.return_value = f"{task_id}:verified"
    mock_provider_factory.return_value = mock_provider

    # Mock engine
    mock_engine.scan.return_value = (False, None)  # Clean

    task_service.process_task(task_data, "scan_normal")

    # Verify engine called
    mock_engine.scan.assert_called_once_with(mock_provider)
    mock_provider_factory.assert_called_with("STREAM", chunks_key=task_id)

    # Verify result pushed to Redis
    mock_redis.rpush.assert_called()
    last_call = mock_redis.rpush.call_args_list[-1]
    assert last_call.args[0] == f"result:{task_id}"
    result_data = json.loads(last_call.args[1].decode("utf-8"))
    assert result_data["status"] == "CLEAN"


def test_process_task_infected(
    task_service, mock_redis, mock_engine, mock_provider_factory
):
    """Test processing a task that is infected"""
    task_id = "task-456"
    push_time = int(time.time_ns())
    task_data = f"{task_id}|STREAM|{push_time}|{task_id}"

    # Mock provider
    mock_provider = MagicMock()
    mock_provider_factory.return_value = mock_provider

    # Mock engine
    mock_engine.scan.return_value = (True, "Eicar-Test-Signature")  # Infected

    task_service.process_task(task_data, "scan_normal")

    # Verify result pushed to Redis
    mock_redis.rpush.assert_called()
    last_call = mock_redis.rpush.call_args_list[-1]
    assert last_call.args[0] == f"result:{task_id}"
    result_data = json.loads(last_call.args[1].decode("utf-8"))
    assert result_data["status"] == "INFECTED"
    assert result_data["virus"] == "Eicar-Test-Signature"
