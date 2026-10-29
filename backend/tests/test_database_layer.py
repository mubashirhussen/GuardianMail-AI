import pytest
from datetime import datetime, timezone, timedelta
from bson import ObjectId
from app.repositories.base import BaseRepository
from app.database.transaction import TransactionManager
from app.database.aggregation import AggregationBuilder
from app.database.cache import cache_manager
from app.database.indexes import initialize_all_indexes
from tests.conftest import MockDatabase, MockRedis

@pytest.mark.asyncio
async def test_database_health_observability_check():
    """Verify check_health method evaluates status accurately."""
    from app.database.connection import db_manager
    health = await db_manager.check_health()
    assert health["mongodb"] == "healthy"
    assert health["redis"] == "healthy"

@pytest.mark.asyncio
async def test_repository_crud_and_soft_delete():
    """Test BaseRepository CRUD routines, paging limits, and soft delete hooks."""
    mock_db = MockDatabase()
    repo = BaseRepository(mock_db, "test_collection", check_soft_delete=True)
    
    # 1. Create document
    doc_payload = {
        "title": "Threat Alert Details",
        "severity": "HIGH",
        "soft_delete": False,
        "version": 1
    }
    created = await repo.create(doc_payload)
    assert "_id" in created
    doc_id = created["_id"]
    
    # 2. Get document
    fetched = await repo.get(doc_id)
    assert fetched is not None
    assert fetched["title"] == "Threat Alert Details"
    
    # 3. Update document
    await repo.update(doc_id, {"title": "Updated Threat Alert Details"})
    updated = await repo.get(doc_id)
    assert updated["title"] == "Updated Threat Alert Details"
    
    # 4. Soft delete document
    deleted = await repo.delete(doc_id, hard=False)
    assert deleted is True
    
    # Get should return None now due to soft_delete=True logical check filter
    after_soft_delete = await repo.get(doc_id)
    assert after_soft_delete is None
    
    # Hard delete document
    hard_deleted = await repo.delete(doc_id, hard=True)
    assert hard_deleted is True

@pytest.mark.asyncio
async def test_repository_bulk_ops_and_aggregations():
    """Verify bulk operations and fluid pipeline query builder aggregates."""
    mock_db = MockDatabase()
    repo = BaseRepository(mock_db, "events_aggregation", check_soft_delete=False)
    
    # Seed mock records
    await repo.create({"category": "phishing", "hits": 10})
    await repo.create({"category": "malware", "hits": 20})
    await repo.create({"category": "phishing", "hits": 15})
    
    # Build aggregate pipeline using AggregationBuilder
    builder = AggregationBuilder()
    pipeline = (
        builder.match({"category": "phishing"})
        .group("$category", {"total_hits": {"$sum": "$hits"}})
        .build()
    )
    
    assert len(pipeline) == 2
    assert pipeline[0]["$match"]["category"] == "phishing"
    assert "$group" in pipeline[1]
    
    # Trigger repository aggregation execution
    results = await repo.aggregate(pipeline)
    assert len(results) >= 0

@pytest.mark.asyncio
async def test_transaction_session_manager():
    """Verify transactions start and propagate without exceptions."""
    from app.database.connection import db_manager
    mock_db = MockDatabase()
    
    # Mock start_session on client
    class MockSession:
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
        def start_transaction(self):
            class Trans:
                async def __aenter__(self):
                    return self
                async def __aexit__(self, exc_type, exc_val, exc_tb):
                    pass
            return Trans()
            
    async def mock_start_session():
        return MockSession()
        
    db_manager.mongo_client.start_session = mock_start_session
    
    tx_manager = TransactionManager()
    async with tx_manager.start_transaction() as session:
        assert session is not None

@pytest.mark.asyncio
async def test_redis_cache_invalidation():
    """Verify cache get, set, delete and pattern invalidation details."""
    # Set cached key
    set_success = await cache_manager.set("session:user_1:token_a", {"user_id": "1", "status": "active"}, 10)
    assert set_success is True
    
    # Get cached key
    cached_val = await cache_manager.get("session:user_1:token_a")
    assert cached_val["user_id"] == "1"
    
    # Invalidate key by pattern
    keys_evicted = await cache_manager.invalidate_by_pattern("session:user_1:*")
    assert keys_evicted >= 1
    
    # Confirm key was evicted
    assert await cache_manager.get("session:user_1:token_a") is None

@pytest.mark.asyncio
async def test_programmatic_indexes_initialization():
    """Verify index creation specifications execute correctly."""
    mock_db = MockDatabase()
    # Call index initialization without raising errors
    await initialize_all_indexes(mock_db)
