import redis
from dependency_injector import containers, providers

from ..common.providers import (
    InlineStreamProvider,
    RedisStreamProvider,
    SharedDiskStreamProvider,
)
from .coordinator import ClusterCoordinator
from .engine import ScannerEngine
from .handler import VirusScanHandler
from .service import ScannerTaskService
from .settings import Settings


class Container(containers.DeclarativeContainer):
    config = providers.Configuration()

    settings = providers.Singleton(
        Settings,
        redis_host=config.redis_host,
        redis_port=config.redis_port,
        clamd_url=config.clamd_url,
        queues=config.queues,
        scan_mount=config.scan_mount,
        enable_memory_check=config.enable_memory_check,
        min_free_memory_mb=config.min_free_memory_mb,
    )

    redis_client = providers.Singleton(
        redis.Redis,
        host=config.redis_host,
        port=config.redis_port,
        decode_responses=False,
    )

    # A single aggregate provider that can create any of the stream implementations.
    # This aligns with the "Union" / "Single Provider" design pattern.
    data_provider = providers.FactoryAggregate(
        STREAM=providers.Factory(RedisStreamProvider, redis_client=redis_client),
        PATH=providers.Factory(SharedDiskStreamProvider),
        BODY=providers.Factory(InlineStreamProvider),
    )

    engine = providers.Singleton(ScannerEngine, clamd_url=config.clamd_url)

    coordinator = providers.Singleton(
        ClusterCoordinator, redis_client=redis_client, clamd_url=config.clamd_url
    )

    task_service = providers.Singleton(
        ScannerTaskService,
        redis_client=redis_client,
        settings=settings,
        engine=engine,
        provider_factory=data_provider,
    )

    handler = providers.Singleton(
        VirusScanHandler,
        redis_client=redis_client,
        settings=settings,
        coordinator=coordinator,
        task_service=task_service,
    )
