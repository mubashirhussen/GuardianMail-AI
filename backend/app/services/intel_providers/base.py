from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
import logging
from app.database.cache import cache_manager

logger = logging.getLogger(__name__)

class BaseIntelProvider(ABC):
    """Abstract Base Threat Intelligence Provider (Microsoft Defender & Google Security Standard)."""

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize vendor configurations, check keys, or warm connection pools."""
        pass

    @abstractmethod
    async def lookup(self, indicator: str) -> Dict[str, Any]:
        """Perform reputation check on indicators (IPs, URLs, domains, hashes)."""
        pass

    @abstractmethod
    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        """Convert vendor-specific payload into a standard security schema."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check connection state or API availability."""
        pass

    @abstractmethod
    def confidence(self) -> float:
        """Return provider-specific threat classification confidence factor (0.0 to 1.0)."""
        pass

    def version(self) -> str:
        """Return integration version."""
        return "1.0.0"

    def timeout(self) -> float:
        """API client timeout limit in seconds."""
        return 5.0

    def retry_count(self) -> int:
        """Number of transient failure retry attempts."""
        return 3

    async def get_cached(self, key: str) -> Optional[Any]:
        """Retrieve stored threat search outputs from Redis cache."""
        try:
             return await cache_manager.get(f"intel_cache:{self.__class__.__name__}:{key}")
        except Exception as e:
             logger.warning(f"Cache lookup failed: {str(e)}")
             return None

    async def set_cached(self, key: str, value: Any, ttl: int = 3600) -> None:
        """Save normalized security intelligence logs inside Redis."""
        try:
             await cache_manager.set(f"intel_cache:{self.__class__.__name__}:{key}", value, expire_seconds=ttl)
        except Exception as e:
             logger.warning(f"Cache store failed: {str(e)}")
