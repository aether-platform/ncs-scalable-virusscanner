from abc import ABC, abstractmethod
import os
import logging
import asyncio
from typing import Optional

logger = logging.getLogger(__name__)

class FeatureFlagsProvider(ABC):
    """Abstract base class for feature flag engines."""
    
    @abstractmethod
    async def get_priority(self, tenant_id: str) -> bool:
        """Returns True if the tenant has high priority."""
        pass

class FlagsmithFeatureFlagsProvider(FeatureFlagsProvider):
    """Flagsmith implementation of FeatureFlagsProvider."""
    
    def __init__(self, flagsmith_client, cache_service):
        self.flagsmith = flagsmith_client
        self.cache = cache_service

    async def get_priority(self, tenant_id: str) -> bool:
        if not self.flagsmith:
            return False

        try:
            logger.info(f"Querying Flagsmith for {tenant_id}")
            # Flagsmith SDK is synchronous — run in thread to avoid blocking event loop
            identity_flags = await asyncio.to_thread(
                self.flagsmith.get_identity_flags, identifier=tenant_id
            )
            plan = identity_flags.get_feature_value("scan_plan")
            # IntelligentCacheService has check_priority
            res = (await self.cache.check_priority(plan)) == "high"
            logger.info(f"Flagsmith result for {tenant_id}: {res}")
            return res
        except Exception as e:
            logger.warning(
                f"Flagsmith query failed for {tenant_id}, defaulting to normal: {e}"
            )
            return False

class EnvVarFeatureFlagsProvider(FeatureFlagsProvider):
    """Environment variable implementation of FeatureFlagsProvider."""
    
    async def get_priority(self, tenant_id: str) -> bool:
        # Simple implementation retrieving from environment
        return os.getenv("SCAN_PRIORITY", "normal").lower() == "high"
