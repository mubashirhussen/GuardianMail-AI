import logging
from typing import AsyncGenerator
from contextlib import asynccontextmanager
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorClientSession
from app.database.connection import db_manager

logger = logging.getLogger(__name__)

class TransactionManager:
    """Async context manager handling MongoDB Atlas multi-document client sessions transactions."""
    
    def __init__(self):
        self.client = db_manager.mongo_client

    @asynccontextmanager
    async def start_transaction(self) -> AsyncGenerator[AsyncIOMotorClientSession, None]:
        """Async context manager wrapper initializing MongoDB transactional session contexts."""
        if self.client is None:
             raise RuntimeError("MongoDB client is not connected. Transaction context aborted.")
             
        async with await self.client.start_session() as session:
            async with session.start_transaction():
                try:
                    yield session
                except Exception as e:
                    logger.error(f"Multi-document transaction failed and aborted: {str(e)}")
                    raise
