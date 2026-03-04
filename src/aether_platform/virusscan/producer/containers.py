import os

import redis.asyncio as redis
from dependency_injector import containers, providers
from flagsmith import Flagsmith

from aether_platform.intelligent_cache.application.service import (
    IntelligentCacheService,
)
from aether_platform.intelligent_cache.domain.policy import BypassPolicy
from aether_platform.intelligent_cache.infrastructure.minio_store import MinioFileStore
from aether_platform.intelligent_cache.infrastructure.nfs_store import NfsFileStore

from ..common.providers import (
    InlineStreamProvider,
    RedisStreamProvider,
    SharedDiskStreamProvider,
)
from ..common.queue.provider import RedisQueueProvider, RedisStateStoreProvider
from .application.orchestrator import ScanOrchestrator
from .application.feature_flags import (
    FlagsmithFeatureFlagsProvider,
    EnvVarFeatureFlagsProvider,
)
from .infrastructure.redis_adapter import RedisScanAdapter
from .interfaces.grpc.handler import VirusScannerExtProcHandler
from .interfaces.grpc.sds import SecretDiscoveryHandler
from .settings import ProducerSettings


class ProducerContainer(containers.DeclarativeContainer):
    config = providers.Configuration()
    config.set_default({
        "CA_CERT_PATH": "/etc/egress-ca/tls.crt",
        "CA_KEY_PATH": "/etc/egress-ca/tls.key",
        "FLAGSMITH_ENV_KEY": "dummy-key",
        "MINIO_ENDPOINT": "minio.minio.svc.cluster.local:9000",
        "MINIO_ACCESS_KEY": "admin",
        "MINIO_SECRET_KEY": "minio-admin-password",
        "MINIO_BUCKET": "virusscan",
        "FILE_STORE_BACKEND": "nfs",
        "NFS_CACHE_PATH": "/data/cache",
    })
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

    # Flagsmith Client (Low-level SDK)
    flagsmith_sdk = providers.Singleton(
        Flagsmith,
        environment_key=config.FLAGSMITH_ENV_KEY,
    )

    # File Store (MinIO or NFS, selected by FILE_STORE_BACKEND env var)
    file_store = providers.Selector(
        providers.Callable(os.getenv, "FILE_STORE_BACKEND", "nfs"),
        minio=providers.Singleton(
            MinioFileStore,
            endpoint=config.MINIO_ENDPOINT,
            access_key=config.MINIO_ACCESS_KEY,
            secret_key=config.MINIO_SECRET_KEY,
            bucket=config.MINIO_BUCKET,
            secure=False,
        ),
        nfs=providers.Singleton(
            NfsFileStore,
            base_path=config.NFS_CACHE_PATH,
        ),
    )

    # Intelligent Cache Service (Fully managed by DI)
    bypass_policy = providers.Factory(BypassPolicy)

    cache_service = providers.Singleton(
        IntelligentCacheService,
        provider=state_store_provider,
        policy=bypass_policy,
        file_store=file_store,
    )

    # Feature Flag Providers
    feature_flags = providers.Selector(
        providers.Callable(os.getenv, "FEATURE_FLAG_ENGINE", "envvar"),
        flagsmith=providers.Singleton(
            FlagsmithFeatureFlagsProvider,
            flagsmith_client=flagsmith_sdk,
            cache_service=cache_service,
        ),
        envvar=providers.Singleton(EnvVarFeatureFlagsProvider),
    )

    # Secret Discovery Handler
    sds_handler = providers.Singleton(
        SecretDiscoveryHandler,
        ca_cert_path=config.CA_CERT_PATH,
        ca_key_path=config.CA_KEY_PATH,
    )

    # Interface
    grpc_handler = providers.Singleton(
        VirusScannerExtProcHandler,
        orchestrator=orchestrator,
        cache=cache_service,
        feature_flags=feature_flags,
        settings=settings,
    )
