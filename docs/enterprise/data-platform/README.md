# Security Data Platform & Cold Data Lake Architecture (Workstream E10)

This reference outlines the data platform pipelines, sliding window rate counters using Redis Sorted Sets, partition date folders, and ML feature storage.

---

## 1. Streaming Analytics and Telemetry Pipeline

```
                         Telemetry Inbound
                                │
                                ▼
                       Data Ingestion API
                                │
            ┌───────────────────┴───────────────────┐
            ▼                                       ▼
      Redis Streams Queue                     Sliding Window
            │                                 (Redis Sorted Sets)
            │                                       │
            ▼                                       ▼
    Cold Data Lake ETL                       Rate Count & Spike
    (YYYY-MM-DD partition)                     Alert Trigger
```

---

## 2. Real-Time sliding Window Rate Calculations
To detect event surges or Denial of Service (DoS) attempts without blocking application performance:
- **Redis Sorted Sets**: Tracks timestamps of events using Unix epoch floating points as scores.
- **Eviction Window**: Evaluates incoming events and prunes historical keys older than `60 seconds` via `ZREMRANGEBYSCORE`.
- **Threshold Limit**: Rates exceeding 100 events/minute trigger critical alerts on the SOC dashboard console.

---

## 3. Data Lake partitioning Structure
To support historical queries and batch analytics, incoming records are mapped to standard date partition folders:
- **Format**: `YYYY-MM-DD`
- **Aggregation**: Search tools automatically load only matching partition dates, avoiding full table scans.
