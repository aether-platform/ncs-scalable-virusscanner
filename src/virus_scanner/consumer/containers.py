import redis
from dependency_injector import containers, providers

from .coordinator import ClusterCoordinator
from .engine import ScannerEngine
from .handler import VirusScanHandler
from .providers import BodyProvider, LocalFileProvider, RedisStreamProvider
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
        decode_responses=True,
    )

    redis_stream_provider = providers.Factory(
        RedisStreamProvider, redis_client=redis_client
    )

    local_file_provider = providers.Factory(LocalFileProvider)

    body_provider = providers.Factory(BodyProvider)

    engine = providers.Singleton(ScannerEngine, clamd_url=config.clamd_url)

    coordinator = providers.Singleton(
        ClusterCoordinator, redis_client=redis_client, clamd_url=config.clamd_url
    )

    handler = providers.Singleton(
        VirusScanHandler,
        redis_client=redis_client,
        settings=settings,
        engine=engine,
        coordinator=coordinator,
        stream_factory=redis_stream_provider.provider,
        path_factory=local_file_provider.provider,
        body_factory=body_provider.provider,
    )
