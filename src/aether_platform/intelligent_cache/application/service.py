import hashlib
import logging

from ...virusscan.common.queue.provider import StateStoreProvider
from ..domain.policy import BypassPolicy

logger = logging.getLogger(__name__)


class IntelligentCacheService:
    """
    Application service that orchestrates the bypass logic and cache lookups asynchronously.
    """

    def _get_cache_key(self, uri: str) -> str:
        """Internal helper to generate a consistent cache key for a URI."""
        key_hash = hashlib.sha256(uri.encode()).hexdigest()
        return f"aether:cache:uri:{key_hash}"

    def __init__(self, provider: StateStoreProvider, policy: BypassPolicy):
        """
        Initializes the service.

        Args:
            provider: Storage backend for cache results (Async).
            policy: Domain policy for bypass and prioritization rules.
        """
        self.provider = provider
        self.policy = policy

    async def get_notable_type(self, uri: str) -> str | None:
        """
        Identifies if the URI belongs to a notable category (e.g., 'docker').
        """
        # Policy checks are currently sync, but we make this async for future-proofing
        return self.policy.get_notable_type(uri)

    async def check_priority(self, plan: str) -> str:
        """
        Determines scan priority based on the user's plan.
        """
        if plan in ["premium", "enterprise", "business"]:
            return "high"
        return "normal"

    async def check_cache(self, uri: str) -> bool:
        """
        Determines if the URI should skip scanning due to policy or cache (Async).
        """
        # 1. Domain Policy Check
        if self.policy.should_bypass(uri):
            logger.debug(f"BYPASS: Policy match for {uri}")
            return True

        # 2. Redis Cache Lookup (Async)
        cache_key = self._get_cache_key(uri)
        return await self.provider.exists(cache_key)

    async def store_cache(self, uri: str, ttl: int = 3600):
        """
        Persists a clean scan result to the cache asynchronously.
        """
        cache_key = self._get_cache_key(uri)
        await self.provider.set(cache_key, "1", ex=ttl)
