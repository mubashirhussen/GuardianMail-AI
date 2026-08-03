# SRE & Software Architect Technical Interview Guide

This guide compiles technical talking points, design patterns, and scaling Q&A scenarios to help showcase **GuardianMail AI** in job interviews.

---

## 1. High-Level Architectural Summary
> **Question: How is the system structured and why did you select this design?**

**Answer**: GuardianMail AI is built following clean architecture and twelve-factor app standards. The backend is built using FastAPI (async python) to ensure fast, asynchronous request handling. Data processing, OCR scanning, and AI threat inference are computationally expensive and would block request execution threads if handled in FastAPI. Therefore, we decoupled these tasks using Celery worker nodes backed by a Redis message broker. MongoDB Atlas is used as our document store, and Nginx serves as the reverse proxy gateway, enforcing rate limiting and security headers.

---

## 2. Horizontal Scalability & Statelessness
> **Question: How does the platform scale to support millions of emails?**

**Answer**: The FastAPI backend is entirely stateless. Sessions are managed using signed JWT tokens and validated using a distributed Redis blacklist cache. This statelessness allows backend nodes to scale horizontally behind a round-robin load balancer without session data loss. Celery worker clusters can similarly scale horizontally, consuming tasks from shared Redis queues.

---

## 3. Database Performance & Indexes
> **Question: How did you optimize MongoDB queries as the dataset grows?**

**Answer**: We audited all application query paths to ensure they rely on specific index lookups instead of full collection scans:
1. Created a compound index on `(user_id_1, date_-1)` to support fast sorted dashboard lookups.
2. Built a text search index on email subjects and body text to allow fast prefix matching.
3. Implemented a TTL index on background job entries to automatically purge records older than 30 days, keeping the working index size small.

---

## 4. Secure Coding & ASVS Hardening
> **Question: What security measures did you implement to protect the platform?**

**Answer**: We hardened the application according to OWASP ASVS guidelines:
1. **Filename Sanitization**: Upload endpoints extract filenames using `os.path.basename` and validate them against an allowed extension whitelist to prevent path traversal and double-extension attacks.
2. **Container Security**: Hardened the Docker entrypoints by switching execution from `root` to a dedicated `appuser` (UID 10001) to prevent container breakout.
3. **CORS & Rate Limiting**: Whitelisted specific origins in CORS configs and restricted API traffic using Nginx rate-limiting zones.
