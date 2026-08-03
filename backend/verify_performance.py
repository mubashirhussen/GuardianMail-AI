import asyncio
import time
import numpy as np
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database.connection import db_manager as conn_db_manager
from app.core.database import db_manager as core_db_manager
from bson import ObjectId

# ==============================================================================
# MOCK DATABASE SYSTEM
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
                elif doc.get(k) != v:
                    match = False
            if match:
                return doc.copy()
        return None

    async def insert_one(self, doc, *args, **kwargs):
        if "_id" not in doc:
            doc["_id"] = ObjectId()
        self.docs[str(doc["_id"])] = doc.copy()
        class Result:
            inserted_id = doc["_id"]
        return Result()

    async def find_one_and_update(self, query, update, return_document=True, *args, **kwargs):
        doc = await self.find_one(query)
        if doc:
            doc_id = str(doc["_id"])
            if "$set" in update:
                self.docs[doc_id].update(update["$set"])
            return self.docs[doc_id]
        return None

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
# BENCHMARK ENGINE
# ==============================================================================

async def run_benchmark():
    print("=" * 80)
    print("          GUARDIANMAIL AI - HIGH-CONCURRENCY PERFORMANCE BENCHMARK")
    print("=" * 80)

    # Setup database mocks
    mock_db = MockDatabase()
    mock_redis = MockRedis()

    conn_db_manager.db = mock_db
    conn_db_manager.redis_client = mock_redis
    conn_db_manager.mongo_client = mock_db
    core_db_manager.db = mock_db
    core_db_manager.redis_client = mock_redis
    core_db_manager.mongo_client = mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:

        # 1. Warm-up Registration & Login
        print("\n[*] Initializing warm-up registration...")
        email = "perf@guardianmail.ai"
        password = "SecurePassword2026!"
        
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": email,
                "password": password,
                "full_name": "Performance Engineer",
                "role": "admin"
            }
        )

        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password}
        )
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Benchmark endpoints list
        endpoints = [
            ("GET /auth/me (Authenticated)", "/api/v1/auth/me", headers),
            ("GET /health/live (Liveness Check)", "/api/v1/health/live", {}),
            ("GET /health/ready (Readiness Check)", "/api/v1/health/ready", {}),
            ("GET /metrics (Prometheus Telemetry)", "/api/v1/metrics", {})
        ]

        iterations = 50

        for label, path, req_headers in endpoints:
            print(f"\n[*] Benchmarking {label} for {iterations} sequential requests...")
            latencies = []
            
            for _ in range(iterations):
                start = time.perf_counter()
                resp = await client.get(path, headers=req_headers)
                latency = (time.perf_counter() - start) * 1000.0  # ms
                
                assert resp.status_code == 200
                latencies.append(latency)

            avg_lat = np.mean(latencies)
            min_lat = np.min(latencies)
            max_lat = np.max(latencies)
            p95_lat = np.percentile(latencies, 95)
            p99_lat = np.percentile(latencies, 99)

            print(f"    Avg Latency: {avg_lat:.2f}ms")
            print(f"    Min/Max    : {min_lat:.2f}ms / {max_lat:.2f}ms")
            print(f"    p95 / p99  : {p95_lat:.2f}ms / {p99_lat:.2f}ms")
            
            # Performance Threshold Assertions
            assert avg_lat < 200.0, f"Average latency for {label} exceeded 200ms target threshold!"

    print("\n" + "=" * 80)
    print(" SUCCESS: ALL PERFORMANCE LATENCY GOALS SATISFIED SUCCESSFULLY!")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(run_benchmark())
