import asyncio
import pytest
from httpx import AsyncClient
from app.main import app
from app.database.connection import db_manager as conn_db_manager
from app.core.database import db_manager as core_db_manager
from bson import ObjectId

# ─── MOCK DATABASE SYSTEM ────────────────────────────────────────────────────

class MockCollection:
    def __init__(self, name):
        self.name = name
        self.docs = {}

    async def find_one(self, query, *args, **kwargs):
        for doc in self.docs.values():
            match = True
            for k, v in query.items():
                if k == "_id" and not isinstance(v, dict):
                    if str(doc.get("_id")) != str(v):
                        match = False
                elif isinstance(v, dict) and "$ne" in v:
                    val = doc.get(k)
                    if str(val) == str(v["$ne"]):
                        match = False
                elif k == "$or":
                    or_match = False
                    for sub_query in v:
                        sub_match = True
                        for sk, sv in sub_query.items():
                            if doc.get(sk) != sv:
                                sub_match = False
                                break
                        if sub_match:
                            or_match = True
                            break
                    if not or_match:
                        match = False
                elif k == "$in" or (isinstance(v, dict) and "$in" in v):
                    allowed = v["$in"] if isinstance(v, dict) else v
                    val = doc.get(k)
                    if isinstance(val, list):
                        if not any(item in allowed for item in val):
                            match = False
                    elif val not in allowed:
                        match = False
                elif doc.get(k) != v:
                    match = False
            if match:
                c = doc.copy()
                return c
        return None

    async def insert_one(self, doc, *args, **kwargs):
        if "_id" not in doc:
            doc["_id"] = ObjectId()
        self.docs[str(doc["_id"])] = doc.copy()
        
        class InsertResult:
            inserted_id = doc["_id"]
        return InsertResult()

    async def find_one_and_update(self, query, update, return_document=True, *args, **kwargs):
        doc = await self.find_one(query)
        if doc:
            doc_id = str(doc["_id"])
            if "$set" in update:
                self.docs[doc_id].update(update["$set"])
            return self.docs[doc_id]
        return None

    async def delete_one(self, query, *args, **kwargs):
        doc = await self.find_one(query)
        if doc:
            self.docs.pop(str(doc["_id"]), None)
            class DeleteResult:
                deleted_count = 1
            return DeleteResult()
        
        class DeleteResult:
            deleted_count = 0
        return DeleteResult()

    async def delete_many(self, query, *args, **kwargs):
        cursor = self.find(query)
        items = await cursor.to_list()
        count = 0
        for item in items:
            self.docs.pop(str(item["_id"]), None)
            count += 1
        class DeleteResult:
            deleted_count = count
        return DeleteResult()

    def find(self, query=None, *args, **kwargs):
        if query is None:
            query = {}
        matching = []
        for doc in self.docs.values():
            match = True
            for k, v in query.items():
                if k == "_id" and not isinstance(v, dict):
                    if str(doc.get("_id")) != str(v):
                        match = False
                elif k == "$or":
                    or_match = False
                    for sub_query in v:
                        sub_match = True
                        for sk, sv in sub_query.items():
                            if doc.get(sk) != sv:
                                sub_match = False
                                break
                        if sub_match:
                            or_match = True
                            break
                    if not or_match:
                        match = False
                elif isinstance(v, dict) and "$ne" in v:
                    if str(doc.get(k)) == str(v["$ne"]):
                        match = False
                elif isinstance(v, dict) and "$in" in v:
                    val = doc.get(k)
                    allowed = v["$in"]
                    if isinstance(val, list):
                        if not any(item in allowed for item in val):
                            match = False
                    elif val not in allowed:
                        match = False
                elif isinstance(v, dict) and "$regex" in v:
                    import re
                    pattern = v["$regex"]
                    flags = re.IGNORECASE if "i" in v.get("$options", "") else 0
                    if not re.search(pattern, str(doc.get(k, "")), flags):
                        match = False
                elif doc.get(k) != v:
                    match = False
            if match:
                matching.append(doc.copy())

        class MockCursor:
            def __init__(self, items):
                self.items = items
            def sort(self, *args, **kwargs):
                return self
            def skip(self, *args, **kwargs):
                return self
            def limit(self, *args, **kwargs):
                return self
            async def to_list(self, length=100):
                return self.items[:length]
        return MockCursor(matching)

    async def count_documents(self, query, *args, **kwargs):
        cursor = self.find(query)
        items = await cursor.to_list()
        return len(items)

    async def create_index(self, *args, **kwargs):
        return "index_mock"

    async def update_one(self, query, update, *args, **kwargs):
        doc = await self.find_one(query)
        count = 0
        if doc:
            doc_id = str(doc["_id"])
            if "$set" in update:
                self.docs[doc_id].update(update["$set"])
                count = 1
        class UpdateResult:
            modified_count = count
            matched_count = count
        return UpdateResult()

    def aggregate(self, pipeline, *args, **kwargs):
        class MockCursor:
            def __init__(self, items):
                self.items = items
            async def to_list(self, length=None):
                return self.items
        return MockCursor(list(self.docs.values()))

    async def update_many(self, query, update, *args, **kwargs):
        cursor = self.find(query)
        items = await cursor.to_list()
        count = 0
        for item in items:
            doc_id = str(item["_id"])
            if "$set" in update:
                self.docs[doc_id].update(update["$set"])
                count += 1
        class Result:
            modified_count = count
        return Result()

class MockDatabase:
    def __init__(self):
        self.collections = {}

    def __getitem__(self, name):
        if name not in self.collections:
            self.collections[name] = MockCollection(name)
        return self.collections[name]

    async def command(self, *args, **kwargs):
        return {"ok": 1.0}

class MockRedis:
    def __init__(self):
        self.store = {}

    async def ping(self):
        return True

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None):
        self.store[key] = str(value)
        return True

    async def delete(self, key):
        self.store.pop(key, None)
        return True

    async def keys(self, pattern):
        import fnmatch
        return [k for k in self.store.keys() if fnmatch.fnmatch(k, pattern)]

    async def is_session_active(self, token_id):
        # Used if sessions are tracked via Redis
        return True

    async def aclose(self):
        pass

# ─── PYTEST FIXTURES ─────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def event_loop():
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session", autouse=True)
async def initialize_db():
    # Override connect/disconnect with in-memory mocks
    mock_db = MockDatabase()
    mock_redis = MockRedis()
    
    # Configure Celery in eager mode to avoid Redis broker connection attempts
    from app.core.celery_app import celery_app
    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = True
    
    async def mock_connect():
        conn_db_manager.db = mock_db
        conn_db_manager.redis_client = mock_redis
        conn_db_manager.mongo_client = mock_db
        
        core_db_manager.db = mock_db
        core_db_manager.redis_client = mock_redis
        core_db_manager.mongo_client = mock_db
        
    async def mock_disconnect():
        pass
        
    conn_db_manager.connect = mock_connect
    conn_db_manager.disconnect = mock_disconnect
    core_db_manager.connect = mock_connect
    core_db_manager.disconnect = mock_disconnect
    
    await conn_db_manager.connect()
    yield

@pytest.fixture
async def client() -> AsyncClient:
    from httpx import ASGITransport
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
