import hashlib
from unittest.mock import MagicMock

import pytest

from aether_platform.intelligent_cache.application.service import \
    IntelligentCacheService


@pytest.fixture
def mock_provider():
    return MagicMock()


@pytest.fixture
def mock_policy():
    return MagicMock()


@pytest.fixture
def service(mock_provider, mock_policy):
    return IntelligentCacheService(mock_provider, mock_policy)


def test_check_cache_hit(service, mock_provider):
    uri = "http://example.com/clean_file.zip"
    expected_hash = hashlib.sha256(uri.encode()).hexdigest()
    expected_key = f"aether:cache:uri:{expected_hash}"

    # Setup mock to simulate cache hit
    mock_provider.exists.return_value = True

    assert service.check_cache(uri) is True
    mock_provider.exists.assert_called_once_with(expected_key)


def test_check_cache_miss(service, mock_provider):
    uri = "http://example.com/new_file.zip"

    # Setup mock to simulate cache miss
    mock_provider.exists.return_value = False

    assert service.check_cache(uri) is False


def test_store_cache(service, mock_provider):
    uri = "http://example.com/clean_file.zip"
    expected_hash = hashlib.sha256(uri.encode()).hexdigest()
    expected_key = f"aether:cache:uri:{expected_hash}"

    service.store_cache(uri)

    mock_provider.set.assert_called_once_with(expected_key, "1", ex=3600)


def test_store_cache_custom_ttl(service, mock_provider):
    uri = "http://example.com/clean_file.zip"
    expected_hash = hashlib.sha256(uri.encode()).hexdigest()
    expected_key = f"aether:cache:uri:{expected_hash}"

    service.store_cache(uri, ttl=7200)

    mock_provider.set.assert_called_once_with(expected_key, "1", ex=7200)
