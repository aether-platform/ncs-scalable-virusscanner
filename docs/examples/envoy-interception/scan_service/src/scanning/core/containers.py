import redis
from dependency_injector import containers, providers
from flagsmith import Flagsmith
from flagsmith.openfeature import FlagsmithProvider
from openfeature import api

from ..common.providers.redis_stream import RedisStreamProvider


class Container(containers.DeclarativeContainer):
    config = providers.Configuration()

    redis_client = providers.Singleton(
        redis.Redis,
        host=config.redis_host,
        port=config.redis_port,
        decode_responses=False,
    )

    redis_meta = providers.Singleton(
        redis.Redis,
        host=config.redis_host,
        port=config.redis_port,
        decode_responses=True,
    )

    # Flagsmith & OpenFeature
    flagsmith_client = providers.Singleton(
        Flagsmith,
        environment_key=config.flagsmith_env_key,
    )

    feature_provider = providers.Singleton(
        FlagsmithProvider,
        client=flagsmith_client,
    )

    # Data Providers
    data_provider_factory = providers.FactoryAggregate(
        STREAM=providers.Factory(RedisStreamProvider, redis_client=redis_client),
    )


class FeatureFlagService:
    def __init__(self, provider: FlagsmithProvider):
        api.set_provider(provider)
        self._client = api.get_client()

    def is_feature_enabled(self, feature_key: str, default: bool = False) -> bool:
        try:
            return self._client.get_boolean_value(feature_key, default)
        except Exception:
            return default

    @property
    def is_high_priority(self):
        return self.is_feature_enabled("high_priority_mode", False)
