import redis
from dependency_injector import containers, providers
from .settings import Settings
from .handler import VirusScanHandler

class Container(containers.DeclarativeContainer):
    config = providers.Configuration()

    settings = providers.Singleton(
        Settings,
        redis_host=config.redis_host,
        redis_port=config.redis_port,
        clamd_url=config.clamd_url,
        queues=config.queues,
        scan_mount=config.scan_mount
    )

    redis_client = providers.Singleton(
        redis.Redis,
        host=config.redis_host,
        port=config.redis_port,
        decode_responses=True
    )

    handler = providers.Singleton(
        VirusScanHandler,
        redis_client=redis_client,
        settings=settings
    )
