import logging
import json
from typing import Any, Optional, Union
from app.database.connection import db_manager

logger = logging.getLogger(__name__)

class CacheManager:
    """Redis cache manager supporting session storage, OTP cache, and temporary scan cache metrics."""
    
    def __init__(self):
        # Access the redis client dynamically via singleton connection pool
        pass

    @property
    def client(self):
        if db_manager.redis_client is None:
             raise RuntimeError("Redis connection pool is not connected. Caching service aborted.")
        return db_manager.redis_client

    async def get(self, key: str) -> Optional[Any]:
        """Fetch value from cache, automatically deserializing JSON data formats."""
        try:
            val = await self.client.get(key)
            if val is not None:
                try:
                    return json.loads(val)
                except json.JSONDecodeError:
                    return val
            return None
        except Exception as e:
            logger.error(f"Redis get key failed for '{key}': {str(e)}")
            return None

    async def set(self, key: str, value: Any, expire_seconds: Optional[int] = None) -> bool:
        """Store value inside cache, converting structures to serializable JSON strings."""
        try:
            val_str = json.dumps(value) if not isinstance(value, (str, int, float, bool)) else str(value)
            if expire_seconds:
                await self.client.set(key, val_str, ex=expire_seconds)
            else:
                await self.client.set(key, val_str)
            return True
        except Exception as e:
            logger.error(f"Redis set key failed for '{key}': {str(e)}")
            return False

    async def delete(self, key: str) -> bool:
        """Evict a specific key from cache."""
        try:
            result = await self.client.delete(key)
            return result > 0
        except Exception as e:
            logger.error(f"Redis delete key failed for '{key}': {str(e)}")
            return False

    async def invalidate_by_pattern(self, pattern: str) -> int:
        """Evict multiple keys matching a glob pattern (Pattern Invalidation)."""
        try:
            count = 0
            # Retrieve keys matching glob pattern
            keys = await self.client.keys(pattern)
            if keys:
                for key in keys:
                    await self.client.delete(key)
                    count += 1
            return count
        except Exception as e:
            logger.error(f"Redis key pattern invalidation failed for '{pattern}': {str(e)}")
            return 0

# Cache Manager instantiated singleton
cache_manager = CacheManager()
