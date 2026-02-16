import hashlib
from unittest.mock import MagicMock

import pytest

from virus_scanner.producer.service import StreamScannerService


@pytest.fixture
def mock_redis():
    return MagicMock()


@pytest.fixture
def service(mock_redis):
    # Mock settings and provider_factory as they are required for init
    return StreamScannerService(mock_redis, MagicMock(), MagicMock())


def test_check_cache_hit(service, mock_redis):
    uri = "http://example.com/clean_file.zip"
    expected_hash = hashlib.sha256(uri.encode()).hexdigest()
    expected_key = f"virus_scan:cache:{expected_hash}"

    # Setup mock to simulate cache hit
    mock_redis.exists.return_value = 1

    assert service.check_cache(uri) is True
    mock_redis.exists.assert_called_once_with(expected_key)


def test_check_cache_miss(service, mock_redis):
    uri = "http://example.com/new_file.zip"

    # Setup mock to simulate cache miss
    mock_redis.exists.return_value = 0

    assert service.check_cache(uri) is False


def test_store_cache(service, mock_redis):
    uri = "http://example.com/clean_file.zip"
    expected_hash = hashlib.sha256(uri.encode()).hexdigest()
    expected_key = f"virus_scan:cache:{expected_hash}"

    service.store_cache(uri)

    mock_redis.set.assert_called_once_with(expected_key, "1", ex=3600)


def test_store_cache_custom_ttl(service, mock_redis):
    uri = "http://example.com/clean_file.zip"
    expected_hash = hashlib.sha256(uri.encode()).hexdigest()
    expected_key = f"virus_scan:cache:{expected_hash}"

    service.store_cache(uri, ttl=7200)

    mock_redis.set.assert_called_once_with(expected_key, "1", ex=7200)
