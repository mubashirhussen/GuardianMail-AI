import asyncio
import sys
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database.connection import db_manager as conn_db_manager
from app.core.database import db_manager as core_db_manager
from bson import ObjectId

# ==============================================================================
# MOCK INFRASTRUCTURE (Self-contained in-memory drivers for verification checks)
# ==============================================================================

class MockCollection:
    def __init__(self, name):
        self.name = name
        self.docs = {}

    async def find_one(self, query, *args, **kwargs):
        for doc in self.docs.values():
            match = True
            for k, v in query.items():
                if k == "_id":
                    if str(doc.get("_id")) != str(v):
                        match = False
                elif k == "$in" or (isinstance(v, dict) and "$in" in v):
                    allowed = v["$in"] if isinstance(v, dict) else v
                    val = doc.get(k)
                    if val not in allowed:
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

    def find(self, query=None, *args, **kwargs):
        if query is None:
            query = {}
        matching = []
        for doc in self.docs.values():
            match = True
            for k, v in query.items():
                if k == "_id":
                    if str(doc.get("_id")) != str(v):
                        match = False
                elif isinstance(v, dict) and "$ne" in v:
                    if doc.get(k) == v["$ne"]:
                        match = False
                elif isinstance(v, dict) and "$in" in v:
                    if doc.get(k) not in v["$in"]:
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
    async def aclose(self):
        pass

# ==============================================================================
# INTEGRATION Lifecycle Test Cases
# ==============================================================================

async def run_lifecycle():
    print("=" * 80)
    print("          GUARDIANMAIL AI - SYSTEM INTEGRATION VERIFICATION")
    print("=" * 80)

    # Inject Mocks
    mock_db = MockDatabase()
    mock_redis = MockRedis()

    conn_db_manager.db = mock_db
    conn_db_manager.redis_client = mock_redis
    conn_db_manager.mongo_client = mock_db
    core_db_manager.db = mock_db
    core_db_manager.redis_client = mock_redis
    core_db_manager.mongo_client = mock_db

    # Initialize Celery in Eager Mode
    from app.workers.celery_app import celery_app
    celery_app.conf.task_always_eager = True

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:

        # Step 1: User Registration
        print("\n[STEP 1] Testing User Registration...")
        email = "verification@guardianmail.ai"
        password = "SecurePassword2026!"
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": email,
                "password": password,
                "full_name": "SRE Verification Engineer",
                "role": "admin"
            }
        )
        print(f"Status: {reg_resp.status_code}, Payload: {reg_resp.json()}")
        assert reg_resp.status_code == 201

        # Step 2: Authentication (Login)
        print("\n[STEP 2] Testing User Login...")
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password}
        )
        print(f"Status: {login_resp.status_code}")
        assert login_resp.status_code == 200
        token_data = login_resp.json()
        access_token = token_data["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}

        # Step 3: Fetch Active User Identity Context
        print("\n[STEP 3] Testing /auth/me Context...")
        me_resp = await client.get("/api/v1/auth/me", headers=headers)
        print(f"Status: {me_resp.status_code}, User: {me_resp.json().get('email')}")
        assert me_resp.status_code == 200

        # Step 4: Mock an Ingested Email Scan Record for Escalation
        print("\n[STEP 4] Injecting Scanned Email mock details...")
        email_oid = ObjectId()
        await mock_db["emails"].insert_one({
            "_id": email_oid,
            "user_id": str(me_resp.json().get("_id")),
            "subject": "Phishing Alert: Bank Account Suspended",
            "from_address": "spoof@suspicious-bank-alert.com",
            "to_address": email,
            "date": "2026-08-02T12:00:00Z",
            "soft_delete": False,
            "analysis": {
                "verdict": "PHISHING",
                "risk_score": 0.95,
                "confidence_score": 0.88,
                "explanation": "Spoofed email domain with suspicious link."
            }
        })

        # Step 5: Escalate Threat Email to Security Incident Ticket
        print("\n[STEP 5] Testing Incident Escalation...")
        inc_resp = await client.post(
            "/api/v1/incidents",
            headers=headers,
            json={
                "email_id": str(email_oid),
                "priority": "HIGH",
                "investigation_notes": "Automated SRE escalation verify run."
            }
        )
        print(f"Status: {inc_resp.status_code}, Incident: {inc_resp.json().get('incident_id')}")
        assert inc_resp.status_code == 201
        incident_id = inc_resp.json().get("id")

        # Step 6: Query SRE Health diagnostic endpoints
        print("\n[STEP 6] Testing Health Diagnostics endpoints...")
        paths = ["/health/live", "/health/ready", "/database", "/redis"]
        for p in paths:
            h_resp = await client.get(f"/api/v1{p}")
            print(f"Path: {p}, Status: {h_resp.status_code}, Response: {h_resp.json()}")
            assert h_resp.status_code == 200

        # Step 7: Export Observability statistics logs
        print("\n[STEP 7] Pulling Prometheus Metrics...")
        metrics_resp = await client.get("/api/v1/metrics")
        print(f"Status: {metrics_resp.status_code}, Metrics Count: {len(metrics_resp.text)} chars")
        assert metrics_resp.status_code == 200

        print("\n" + "=" * 80)
        print(" SUCCESS: ALL SYSTEM INTEGRATION CHECKLISTS PASSED SUCCESSFULLY!")
        print("=" * 80)

if __name__ == "__main__":
    asyncio.run(run_lifecycle())
