import redis
from dependency_injector import containers, providers

from ..common.providers import (
    InlineStreamProvider,
    RedisStreamProvider,
    SharedDiskStreamProvider,
)
from .service import StreamScannerService
from .settings import ProducerSettings


class ProducerContainer(containers.DeclarativeContainer):
    config = providers.Configuration()

    settings = providers.Singleton(
        ProducerSettings,
        redis_host=config.redis_host,
        redis_port=config.redis_port,
        scan_tmp_dir=config.scan_tmp_dir,
        scan_file_threshold_mb=config.scan_file_threshold_mb,
    )

    redis_client = providers.Singleton(
        redis.Redis,
        host=config.redis_host,
        port=config.redis_port,
        decode_responses=False,
    )

    data_provider = providers.FactoryAggregate(
        STREAM=providers.Factory(RedisStreamProvider, redis_client=redis_client),
        PATH=providers.Factory(SharedDiskStreamProvider),
        BODY=providers.Factory(InlineStreamProvider),
    )

    scanner_service = providers.Singleton(
        StreamScannerService,
        redis_client=redis_client,
        settings=settings,
        provider_factory=data_provider,
    )
