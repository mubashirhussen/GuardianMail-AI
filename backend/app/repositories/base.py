from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from bson import ObjectId
from pymongo import InsertOne, UpdateOne, DeleteOne
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorCollection, AsyncIOMotorClientSession
import time
import logging
from app.exceptions.custom import DatabaseError

logger = logging.getLogger(__name__)

class BaseRepository:
    """Production-grade MongoDB repository providing CRUD, transactions, soft delete, and bulk ops."""
    
    def __init__(self, db: AsyncIOMotorDatabase, collection_name: str, check_soft_delete: bool = True):
        self.db = db
        self.collection: AsyncIOMotorCollection = db[collection_name]
        self.check_soft_delete = check_soft_delete

    @staticmethod
    def _to_oid(id_val: Union[str, ObjectId]) -> ObjectId:
        """Safely convert hex string or BSON ObjectId representations."""
        if isinstance(id_val, ObjectId):
            return id_val
        try:
            return ObjectId(str(id_val).strip())
        except Exception:
            raise ValueError(f"Invalid BSON ObjectId string format: {id_val}")

    def _apply_soft_delete_filter(self, query: Dict[str, Any]) -> Dict[str, Any]:
        """Inject soft_delete=False criteria if configured."""
        if self.check_soft_delete:
            if "soft_delete" not in query:
                q = query.copy()
                q["soft_delete"] = False
                return q
        return query

    async def get(
        self, 
        id_str: Union[str, ObjectId], 
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> Optional[Dict[str, Any]]:
        """Fetch a single document matching the unique identifier."""
        start = time.perf_counter()
        try:
            oid = self._to_oid(id_str)
            query = self._apply_soft_delete_filter({"_id": oid})
            doc = await self.collection.find_one(query, session=session)
            return doc
        except ValueError:
            return None
        except Exception as e:
            raise DatabaseError(f"Repository get operation failed: {str(e)}")
        finally:
            elapsed = (time.perf_counter() - start) * 1000
            # Telemetry response logging
            if elapsed > 100:  # Log slow queries past 100ms threshold
                 logger.warning(f"Slow query detected: get on {self.collection.name} took {elapsed:.2f}ms", 
                                extra={"duration_ms": elapsed, "collection": self.collection.name})

    async def get_by_field(
        self, 
        field_name: str, 
        field_value: Any, 
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> Optional[Dict[str, Any]]:
        """Fetch a single document matching a specific field criteria."""
        try:
            query = self._apply_soft_delete_filter({field_name: field_value})
            return await self.collection.find_one(query, session=session)
        except Exception as e:
            raise DatabaseError(f"Repository get_by_field failed: {str(e)}")

    async def create(
        self, 
        document: Dict[str, Any], 
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> Dict[str, Any]:
        """Insert a new document."""
        try:
            doc_copy = document.copy()
            if "soft_delete" not in doc_copy:
                doc_copy["soft_delete"] = False
            if "status" not in doc_copy:
                doc_copy["status"] = "active"
            if "version" not in doc_copy:
                doc_copy["version"] = 1
            if "created_at" not in doc_copy:
                doc_copy["created_at"] = datetime.now(timezone.utc)
            if "updated_at" not in doc_copy:
                doc_copy["updated_at"] = datetime.now(timezone.utc)
                
            if "_id" in doc_copy and isinstance(doc_copy["_id"], str):
                 doc_copy["_id"] = self._to_oid(doc_copy["_id"])
            result = await self.collection.insert_one(doc_copy, session=session)
            doc_copy["_id"] = result.inserted_id
            return doc_copy
        except Exception as e:
            raise DatabaseError(f"Repository create failed: {str(e)}")

    async def update(
        self, 
        id_str: Union[str, ObjectId], 
        update_dict: Dict[str, Any], 
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> Optional[Dict[str, Any]]:
        """Modify an existing document matching the given unique identifier."""
        try:
            oid = self._to_oid(id_str)
            query = self._apply_soft_delete_filter({"_id": oid})
            doc_copy = {k: v for k, v in update_dict.items() if k != "_id"}
            result = await self.collection.find_one_and_update(
                query,
                {"$set": doc_copy},
                return_document=True,
                session=session
            )
            return result
        except ValueError:
            return None
        except Exception as e:
            raise DatabaseError(f"Repository update failed: {str(e)}")

    async def delete(
        self, 
        id_str: Union[str, ObjectId], 
        hard: bool = False, 
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> bool:
        """Perform hard deletion or logical soft delete based on parameter."""
        try:
            oid = self._to_oid(id_str)
            if hard:
                result = await self.collection.delete_one({"_id": oid}, session=session)
                return result.deleted_count > 0
            else:
                result = await self.collection.update_one(
                    {"_id": oid},
                    {"$set": {"soft_delete": True}},
                    session=session
                )
                return result.modified_count > 0
        except ValueError:
            return False
        except Exception as e:
            raise DatabaseError(f"Repository delete failed: {str(e)}")

    async def get_multi(
        self, 
        query: Optional[Dict[str, Any]] = None, 
        skip: int = 0, 
        limit: int = 100,
        sort_by: Optional[str] = None,
        sort_desc: bool = False,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> List[Dict[str, Any]]:
        """Fetch a page slice of multiple documents with sorting and pagination."""
        try:
            if query is None:
                query = {}
            query = self._apply_soft_delete_filter(query)
            cursor = self.collection.find(query, session=session).skip(skip).limit(limit)
            if sort_by:
                direction = -1 if sort_desc else 1
                cursor = cursor.sort(sort_by, direction)
            results = await cursor.to_list(length=limit)
            return results
        except Exception as e:
            raise DatabaseError(f"Repository get_multi failed: {str(e)}")

    async def bulk_write(
        self, 
        operations: List[Union[InsertOne, UpdateOne, DeleteOne]], 
        ordered: bool = True,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> Any:
        """Execute multiple database operations in a single round-trip (Bulk Operations)."""
        try:
            if not operations:
                return None
            result = await self.collection.bulk_write(operations, ordered=ordered, session=session)
            return result
        except Exception as e:
            raise DatabaseError(f"Repository bulk_write failed: {str(e)}")

    async def aggregate(
        self, 
        pipeline: List[Dict[str, Any]], 
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> List[Dict[str, Any]]:
        """Execute aggregation pipeline query framework queries."""
        try:
            cursor = self.collection.aggregate(pipeline, session=session)
            return await cursor.to_list(length=None)
        except Exception as e:
            raise DatabaseError(f"Repository aggregation failed: {str(e)}")

    async def count(
        self, 
        query: Optional[Dict[str, Any]] = None,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> int:
        """Count documents matching standard query query."""
        try:
            if query is None:
                query = {}
            query = self._apply_soft_delete_filter(query)
            return await self.collection.count_documents(query, session=session)
        except Exception as e:
            raise DatabaseError(f"Repository count failed: {str(e)}")
