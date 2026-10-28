"""
Database connection manager for MongoDB and Redis.
Handles async connections, connection pooling, and lifecycle management.
"""

import logging
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
import redis.asyncio as redis
from pymongo.errors import ServerSelectionTimeoutError, ConnectionFailure
from typing import Optional
from app.core.config import settings

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages MongoDB and Redis connections."""
    
    def __init__(self):
        self.mongo_client: Optional[AsyncIOMotorClient] = None
        self.db: Optional[AsyncIOMotorDatabase] = None
        self.redis_client: Optional[redis.Redis] = None
    
    async def connect(self) -> None:
        """Initialize MongoDB and Redis client connections with proper pooling."""
        # MongoDB Connection
        try:
            logger.info(f"Connecting to MongoDB at {settings.MONGODB_URL}")
            self.mongo_client = AsyncIOMotorClient(
                settings.MONGODB_URL,
                maxPoolSize=settings.MONGODB_POOL_SIZE,
                minPoolSize=5,
                maxIdleTimeMS=settings.MONGODB_MAX_IDLE_TIME_SECONDS * 1000,
                serverSelectionTimeoutMS=5000,
                socketTimeoutMS=10000,
            )
            
            # Test connection
            await self.mongo_client.admin.command("ping")
            self.db = self.mongo_client[settings.MONGODB_DB_NAME]
            logger.info(
                f"Successfully connected to MongoDB. "
                f"Database: {settings.MONGODB_DB_NAME}, "
                f"Pool Size: {settings.MONGODB_POOL_SIZE}"
            )
            
            # Create indexes
            await self._create_indexes()
            
        except (ServerSelectionTimeoutError, ConnectionFailure) as e:
            logger.error(f"Failed to connect to MongoDB: {str(e)}")
            raise RuntimeError(
                f"Could not connect to MongoDB at {settings.MONGODB_URL}. "
                "Ensure MongoDB is running and connection string is correct."
            ) from e
        except Exception as e:
            logger.error(f"Unexpected MongoDB connection error: {str(e)}")
            raise
        
        # Redis Connection
        try:
            logger.info(f"Connecting to Redis at {settings.REDIS_URL}")
            self.redis_client = redis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=3,
                socket_keepalive=True,
            )
            await self.redis_client.ping()
            logger.info("Successfully connected to Redis.")
        except Exception as e:
            logger.warning(
                f"Redis is unavailable at {settings.REDIS_URL}: {e}. "
                "Operating in in-memory cache fallback mode."
            )
            self.redis_client = None
    
    async def disconnect(self) -> None:
        """Close MongoDB and Redis connections."""
        if self.mongo_client:
            self.mongo_client.close()
            logger.info("MongoDB client connection closed.")
        if self.redis_client:
            await self.redis_client.aclose()
            logger.info("Redis client connection closed.")
    
    async def _create_indexes(self) -> None:
        """Create database indexes for optimal query performance."""
        if self.db is None:
            logger.warning("Database not initialized, skipping index creation")
            return
        
        try:
            # Users collection indexes
            users = self.db["users"]
            await users.create_index("email", unique=True)
            await users.create_index("google_id", sparse=True)
            await users.create_index("created_at")
            await users.create_index("role")
            
            # Emails collection indexes
            emails = self.db["emails"]
            await emails.create_index([("user_id", 1), ("gmail_id", 1)], unique=True)
            await emails.create_index([("user_id", 1), ("received_at", -1)])
            await emails.create_index("sender")
            await emails.create_index([("threat_level", -1), ("created_at", -1)])
            await emails.create_index("status")
            
            # Devices collection indexes
            devices = self.db["devices"]
            await devices.create_index([("user_id", 1), ("device_id", 1)], unique=True)
            await devices.create_index("last_used_at")
            await devices.create_index("is_trusted")
            
            # Sessions collection indexes
            sessions = self.db["sessions"]
            await sessions.create_index([("user_id", 1), ("created_at", -1)])
            await sessions.create_index("expires_at", expireAfterSeconds=0)
            
            # Audit logs collection indexes
            audit_logs = self.db["audit_logs"]
            await audit_logs.create_index([("user_id", 1), ("created_at", -1)])
            await audit_logs.create_index("action")
            await audit_logs.create_index("created_at", expireAfterSeconds=31536000)  # 1 year TTL
            
            # Complaints collection indexes
            complaints = self.db["complaints"]
            await complaints.create_index([("user_id", 1), ("created_at", -1)])
            await complaints.create_index("status")
            
            # Login attempts collection indexes
            login_attempts = self.db["login_attempts"]
            await login_attempts.create_index([("email", 1), ("created_at", -1)])
            await login_attempts.create_index("created_at", expireAfterSeconds=3600)  # 1 hour TTL
            
            logger.info("Database indexes created successfully")
        except Exception as e:
            logger.error(f"Error creating indexes: {str(e)}")
            # Don't raise - indexes not critical for operation


# Global database manager instance
db_manager = DatabaseManager()


async def get_database() -> AsyncIOMotorDatabase:
    """Dependency for getting database connection in routes."""
    if db_manager.db is None:
        raise RuntimeError("Database not connected. Call db_manager.connect() first.")
    return db_manager.db


def get_redis() -> Optional[redis.Redis]:
    """Dependency to retrieve Redis client instance."""
    return db_manager.redis_client
