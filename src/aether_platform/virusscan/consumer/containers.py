import redis.asyncio as redis
from dependency_injector import containers, providers

from aether_platform.virusscan.common.providers import (
    InlineStreamProvider,
    RedisStreamProvider,
    SharedDiskStreamProvider,
)
from aether_platform.virusscan.common.queue.provider import (
    RedisQueueProvider,
    RedisStateStoreProvider,
)
from aether_platform.virusscan.consumer.application.service import ScannerTaskService
from aether_platform.virusscan.consumer.infrastructure.coordinator import (
    ClusterCoordinator,
)
from aether_platform.virusscan.consumer.infrastructure.engine_client import (
    ScannerEngineClient,
)
from aether_platform.virusscan.consumer.interfaces.worker.handler import (
    VirusScanHandler,
)
from aether_platform.virusscan.consumer.settings import Settings


class Container(containers.DeclarativeContainer):
    config = providers.Configuration()
    config.from_env()

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
        host=settings.provided.redis_host,
        port=settings.provided.redis_port,
        decode_responses=False,
    )

    queue_provider = providers.Singleton(
        RedisQueueProvider,
        redis_client=redis_client,
    )

    state_store_provider = providers.Singleton(
        RedisStateStoreProvider,
        redis_client=redis_client,
    )

    data_provider = providers.FactoryAggregate(
        STREAM=providers.Factory(RedisStreamProvider, redis_client=redis_client),
        PATH=providers.Factory(SharedDiskStreamProvider),
        BODY=providers.Factory(InlineStreamProvider),
    )

    # Infrastructure
    engine = providers.Singleton(
        ScannerEngineClient, clamd_url=settings.provided.clamd_url
    )

    coordinator = providers.Singleton(
        ClusterCoordinator,
        queue_provider=queue_provider,
        state_store=state_store_provider,
        clamd_url=settings.provided.clamd_url,
    )

    # Application
    task_service = providers.Singleton(
        ScannerTaskService,
        queue_provider=queue_provider,
        settings=settings,
        engine=engine,
        provider_factory=data_provider,
    )

    # Interface
    handler = providers.Singleton(
        VirusScanHandler,
        queue_provider=queue_provider,
        settings=settings,
        coordinator=coordinator,
        task_service=task_service,
    )
