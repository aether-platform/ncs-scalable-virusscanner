import hashlib
import logging

from ...virusscan.common.queue.provider import StateStoreProvider
from ..domain.policy import BypassPolicy

logger = logging.getLogger(__name__)


class IntelligentCacheService:
    """
    Application service that orchestrates the bypass logic and cache lookups.
    """

    def _get_cache_key(self, uri: str) -> str:
        """Internal helper to generate a consistent cache key for a URI."""
        key_hash = hashlib.sha256(uri.encode()).hexdigest()
        return f"aether:cache:uri:{key_hash}"

    def __init__(self, provider: StateStoreProvider, policy: BypassPolicy):
        """
        Initializes the service.

        Args:
            provider: Storage backend for cache results.
            policy: Domain policy for bypass and prioritization rules.
        """
        self.provider = provider
        self.policy = policy

    def get_notable_type(self, uri: str) -> str | None:
        """
        Identifies if the URI belongs to a notable category (e.g., 'docker').

        Args:
            uri: Request URI.

        Returns:
            Category name or None.
        """
        return self.policy.get_notable_type(uri)

    def check_priority(self, plan: str) -> str:
        """
        Determines scan priority based on the user's plan.

        Args:
            plan: User's purchase option or tier.

        Returns:
            'high' or 'normal'.
        """
        # Logic is centralized in policy or simple mapping
        if plan in ["premium", "enterprise", "business"]:
            return "high"
        return "normal"

    def check_cache(self, uri: str) -> bool:
        """
        Determines if the URI should skip scanning due to policy or cache.

        Args:
            uri: Request URI.

        Returns:
            True if scan can be skipped, False otherwise.
        """
        # 1. Domain Policy Check (Now usually returns False for bypass)
        if self.policy.should_bypass(uri):
            logger.debug(f"BYPASS: Policy match for {uri}")
            return True

        # 2. Redis Cache Lookup
        cache_key = self._get_cache_key(uri)
        return self.provider.exists(cache_key)

    def store_cache(self, uri: str, ttl: int = 3600):
        """
        Persists a clean scan result to the cache.

        Args:
            uri: Request URI.
            ttl: Time-to-live in seconds.
        """
        cache_key = self._get_cache_key(uri)
        self.provider.set(cache_key, "1", ex=ttl)
