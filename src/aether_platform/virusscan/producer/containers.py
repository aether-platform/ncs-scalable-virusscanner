import os

import redis.asyncio as redis
from dependency_injector import containers, providers
from flagsmith import Flagsmith

from aether_platform.intelligent_cache.application.service import (
    IntelligentCacheService,
)
from aether_platform.intelligent_cache.domain.policy import BypassPolicy

from ..common.providers import (
    InlineStreamProvider,
    RedisStreamProvider,
    SharedDiskStreamProvider,
)
from ..common.queue.provider import RedisQueueProvider, RedisStateStoreProvider
from .application.orchestrator import ScanOrchestrator
from .infrastructure.redis_adapter import RedisScanAdapter
from .interfaces.grpc.handler import VirusScannerExtProcHandler
from .settings import ProducerSettings


class ProducerContainer(containers.DeclarativeContainer):
    config = providers.Configuration()
    config.from_dict(os.environ)

    settings = providers.Singleton(
        ProducerSettings,
        redis_host=config.redis_host,
        redis_port=config.redis_port,
        scan_tmp_dir=config.scan_tmp_dir,
        scan_file_threshold_mb=config.scan_file_threshold_mb,
        grpc_port=config.grpc_port,
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
    redis_adapter = providers.Singleton(
        RedisScanAdapter,
        queue_provider=queue_provider,
        state_store=state_store_provider,
    )

    # Application
    orchestrator = providers.Singleton(
        ScanOrchestrator,
        redis_adapter=redis_adapter,
        provider_factory=data_provider,
    )

    # Flagsmith Client
    flagsmith = providers.Singleton(
        Flagsmith,
        environment_key=os.environ.get("FLAGSMITH_ENV_KEY", "dummy-key"),
    )

    # Intelligent Cache Service (Fully managed by DI)
    bypass_policy = providers.Factory(BypassPolicy)

    cache_service = providers.Singleton(
        IntelligentCacheService,
        provider=state_store_provider,
        policy=bypass_policy,
    )

    # Interface
    grpc_handler = providers.Singleton(
        VirusScannerExtProcHandler,
        orchestrator=orchestrator,
        cache=cache_service,
        flagsmith_client=flagsmith,
        settings=settings,
    )
