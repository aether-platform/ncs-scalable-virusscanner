from unittest.mock import MagicMock, patch

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


def test_handler_clean_file(mock_redis, settings):
    """Test handler logic when file is clean"""
    handler = VirusScanHandler(mock_redis, settings)

    # Mock clamd client
    with patch("clamd.ClamdNetworkSocket") as mock_clamd:
        client_instance = mock_clamd.return_value
        client_instance.ping.return_value = "PONG"
        client_instance.scan.return_value = {"/tmp/virusscan/test.txt": ("OK", None)}

        # Simulate file existence
        with patch("os.path.exists", return_value=True):
            result, reason = handler._scan_file("test.txt")

            assert result == "clean"
            assert reason is None
            client_instance.scan.assert_called_once_with("/tmp/virusscan/test.txt")


def test_handler_infected_file(mock_redis, settings):
    """Test handler logic when file is infected"""
    handler = VirusScanHandler(mock_redis, settings)

    with patch("clamd.ClamdNetworkSocket") as mock_clamd:
        client_instance = mock_clamd.return_value
        client_instance.ping.return_value = "PONG"
        client_instance.scan.return_value = {
            "/tmp/virusscan/virus.txt": ("FOUND", "Eicar-Test-Signature")
        }

        with patch("os.path.exists", return_value=True):
            result, reason = handler._scan_file("virus.txt")

            assert result == "infected"
            assert reason == "Eicar-Test-Signature"


def test_handler_process_new_format(mock_redis, settings):
    """Test processing task in taskID|MODE|TIMESTAMP|CONTENT format"""
    handler = VirusScanHandler(mock_redis, settings)

    task_data = "task-123|BODY|123456789|some-content"

    # Mock _scan_with_clamav_stream
    with patch.object(
        handler, "_scan_with_clamav_stream", return_value=(False, "")
    ) as mock_scan:
        handler._process_task_new_format(task_data, "scan_normal")

        mock_scan.assert_called_once()
        # Verify result pushed to Redis
        mock_redis.rpush.assert_called_with("result:task-123", "CLEAN")
        mock_redis.expire.assert_called_with("result:task-123", 60)
