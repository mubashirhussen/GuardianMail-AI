import fnmatch
import json
import logging
import time
from typing import Any, Dict, Optional, Tuple
from app.database.connection import db_manager

logger = logging.getLogger(__name__)

class CacheManager:
    """Cache manager supporting Redis with in-memory TTL dictionary fallback."""
    
    def __init__(self):
        # In-memory fallback dictionary: key -> (value_str, expiry_timestamp)
        self._memory_store: Dict[str, Tuple[str, Optional[float]]] = {}

    @property
    def client(self):
        return db_manager.redis_client

    def _clean_memory_key(self, key: str) -> Optional[str]:
        if key in self._memory_store:
            val, exp = self._memory_store[key]
            if exp is not None and time.time() > exp:
                del self._memory_store[key]
                return None
            return val
        return None

    async def get(self, key: str) -> Optional[Any]:
        """Fetch value from cache, automatically deserializing JSON data formats."""
        if self.client is not None:
            try:
                val = await self.client.get(key)
                if val is not None:
                    try:
                        return json.loads(val)
                    except json.JSONDecodeError:
                        return val
                return None
            except Exception as e:
                logger.debug(f"Redis get key failed for '{key}', falling back to memory store: {e}")

        # Fallback to in-memory store
        val_str = self._clean_memory_key(key)
        if val_str is not None:
            try:
                return json.loads(val_str)
            except json.JSONDecodeError:
                return val_str
        return None

    async def set(self, key: str, value: Any, expire_seconds: Optional[int] = None) -> bool:
        """Store value inside cache, converting structures to serializable JSON strings."""
        val_str = json.dumps(value) if not isinstance(value, (str, int, float, bool)) else str(value)
        exp = (time.time() + expire_seconds) if expire_seconds else None
        self._memory_store[key] = (val_str, exp)

        if self.client is not None:
            try:
                if expire_seconds:
                    await self.client.set(key, val_str, ex=expire_seconds)
                else:
                    await self.client.set(key, val_str)
                return True
            except Exception as e:
                logger.debug(f"Redis set key failed for '{key}', recorded in memory store: {e}")
                return True

        return True

    async def delete(self, key: str) -> bool:
        """Evict a specific key from cache."""
        existed_in_mem = key in self._memory_store
        self._memory_store.pop(key, None)

        if self.client is not None:
            try:
                result = await self.client.delete(key)
                return result > 0 or existed_in_mem
            except Exception as e:
                logger.debug(f"Redis delete failed for '{key}': {e}")

        return existed_in_mem

    async def invalidate_by_pattern(self, pattern: str) -> int:
        """Evict multiple keys matching a glob pattern."""
        count = 0
        matched_keys = [k for k in list(self._memory_store.keys()) if fnmatch.fnmatch(k, pattern)]
        for k in matched_keys:
            self._memory_store.pop(k, None)
            count += 1

        if self.client is not None:
            try:
                keys = await self.client.keys(pattern)
                if keys:
                    for key in keys:
                        await self.client.delete(key)
                        count += 1
            except Exception as e:
                logger.debug(f"Redis pattern invalidation failed for '{pattern}': {e}")

        return count

# Cache Manager instantiated singleton
cache_manager = CacheManager()
