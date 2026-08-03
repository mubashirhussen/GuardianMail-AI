import logging
from motor.motor_asyncio import AsyncIOMotorDatabase
import redis.asyncio as redis
from app.core.database import db_manager as core_db_manager

logger = logging.getLogger(__name__)

class DatabaseManagerWrapper:
    """Wrapper that delegates database client access to core_db_manager, adding compatibility methods."""

    @property
    def db(self):
        return core_db_manager.db

    @db.setter
    def db(self, val):
        core_db_manager.db = val

    @property
    def redis_client(self):
        return core_db_manager.redis_client

    @redis_client.setter
    def redis_client(self, val):
        core_db_manager.redis_client = val

    @property
    def mongo_client(self):
        return core_db_manager.mongo_client

    @mongo_client.setter
    def mongo_client(self, val):
        core_db_manager.mongo_client = val

    async def connect(self) -> None:
        await core_db_manager.connect()

    async def disconnect(self) -> None:
        await core_db_manager.disconnect()

    async def check_health(self) -> dict:
        """Evaluate connectivity state of MongoDB and Redis databases."""
        status = {"mongodb": "unhealthy", "redis": "unhealthy"}
        
        if self.db is not None:
            try:
                await self.db.command("ping")
                status["mongodb"] = "healthy"
            except Exception as e:
                status["mongodb"] = f"unhealthy: {str(e)}"
                
        if self.redis_client is not None:
            try:
                await self.redis_client.ping()
                status["redis"] = "healthy"
            except Exception as e:
                status["redis"] = f"unhealthy: {str(e)}"
                
        return status

# Single source of truth for the database connection manager
db_manager = DatabaseManagerWrapper()

async def get_db() -> AsyncIOMotorDatabase:
    """FastAPI Dependency Injection provider for obtaining MongoDB database client."""
    if db_manager.db is None:
        raise RuntimeError("Database connection not initialized. Check application startup hooks.")
    return db_manager.db

async def get_redis() -> redis.Redis:
    """FastAPI Dependency Injection provider for obtaining Redis connection."""
    if db_manager.redis_client is None:
        raise RuntimeError("Redis connection not initialized. Check application startup hooks.")
    return db_manager.redis_client
