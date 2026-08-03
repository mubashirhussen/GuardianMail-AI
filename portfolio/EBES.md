# Enterprise Backend Engineering Specification: GuardianMail AI

---

## Section 1: Backend Vision

GuardianMail AI's backend is a stateless, asynchronous microservice-ready platform designed to enforce Zero-Trust access and deliver high-concurrency mail analysis:
- **Clean Architecture & Hexagonal Modularity**: Keeps core business logic decoupled from transport protocols (HTTP/FastAPI) and storage adapters (Motor/Redis).
- **Twelve-Factor & Stateless Scaling**: Services run stateless configurations, keeping persistent states inside distributed databases and cache networks.
- **Microservices Ready**: Decouples API ingestion points from asynchronous scanning engines (Celery workers).

---

## Section 2: Backend Folder Structure

```
guardianmail-backend/
├── app/
│   ├── api/
│   │   ├── dependencies/    # FastAPI security & DB injection hooks
│   │   ├── middleware/      # CORS, Logging, and RateLimiters
│   │   └── v1/              # Endpoint routers controllers
│   ├── core/
│   │   ├── config/          # Pydantic Settings loaders
│   │   └── security/        # JWT & Cryptography utilities
│   ├── database/
│   │   ├── connection.py    # Mongo & Redis clients initialization
│   │   └── indexes.py       # MongoDB compound indices builder
│   ├── models/              # Pydantic domain data validation schemas
│   ├── repositories/        # Mongo Generic Repository implementations
│   ├── services/            # Incident, threat, and OCR analyzers
│   └── telemetry/           # OpenTelemetry spans trace builders
└── tests/                   # Pytest integration and negative behaviors suite
```

---

## Section 3: Application Lifecycle

- **Startup Events**: On server bootstrap, initialize connection handlers for MongoDB Atlas and Redis. Check database connection health and construct indices.
- **Graceful Shutdown**: Close active socket connection pools safely. Complete pending queue jobs before exiting container runtimes.

---

## Section 4: Configuration Management

- Settings are loaded via Pydantic `BaseSettings` configurations.
- Environment variables override default values using system profiles (`.env`).
- Secrets and external API keys are loaded directly from environments variables, rejecting hardcoded variables configurations.

---

## Section 5: Dependency Injection (DI)

FastAPI dependencies injection framework manages context lifecycles:
```python
async def get_db() -> AsyncGenerator[AsyncIOMotorDatabase, None]:
    client = await MongoClient.get_client()
    yield client[settings.MONGODB_DB_NAME]
```

---

## Section 6: Authentication & Session Management

- **User Accounts**: Password hashes are processed via Passlib and bcrypt.
- **Session Control**: Session validations use signed JWT tokens (Access and Refresh) passed via HTTP Authorization headers.
- **Blacklists**: Revoked tokens are tracked in Redis cache databases.

---

## Section 7: Authorization & Tenant Isolation

- **Role-Based Access Control (RBAC)**: Enforces access parameters on endpoints using role attributes (`ADMIN`, `SOC_ANALYST`, `USER`).
- **Organization Isolation**: Every index lookups query is constrained by the user's `organization_id` to guarantee tenant isolation.

---

## Section 8: API Design Standards

- **RESTful Routing**: Use plural nouns and standard HTTP verbs (GET, POST, DELETE).
- **Pagination**: Implemented using `limit` and `offset` query parameters.
- **Standardized Responses**: All endpoints return standardized JSON schemas, using proper HTTP status codes.

---

## Section 9: Core API Modules

Core routes are segregated into functional sub-routers:
- `/api/v1/auth`: Registration, login, and Google OAuth credentials check.
- `/api/v1/emails`: synchronization and analysis metadata extraction.
- `/api/v1/attachments`: File scanning, validation, and Tesseract OCR triggers.
- `/api/v1/incidents`: Incident management workspaces.

---

## Section 10: API Endpoints Specifics

### `POST /api/v1/auth/login`
- **Purpose**: Authenticates user and generates JWT access/refresh tokens.
- **Request Schema**: `UserLoginSchema` (username, password).
- **Response Schema**: `TokenResponseSchema` (access_token, refresh_token, token_type).
- **Rate Limit**: 5 requests per minute per IP.
- **Audit Logging**: Logs audit events on failed authentication attempts.

---

## Section 11: Business Services Layer

- **ThreatDetectorService**: Runs threat metrics aggregations across 12 detectors.
- **IncidentResponseService**: Creates incident workspace records, processes evidence packages, and compiles complaints.
- **AttachmentAnalyzerService**: Sanitizes filenames, verifies extensions, and runs Tesseract OCR text recognition.

---

## Section 12: Repository Layer

- **MongoRepository**: Implements common CRUD operations using async Motor drivers.
- **CachingRepository**: Proxies Mongo reads through Redis cache keys to optimize response latencies.

---

## Section 13: AI Integration Layer

- **Risk Scoring**: Computes weighted threats percentages, scaling results from 0 to 100.
- **Model Registry**: Tracks active classification versions to refine model predictions scores.

---

## Section 14: Asynchronous Processing

- **Celery Tasks**: Offloads intensive file scanning, OCR parsing, and PDF document generation.
- **Retry Policy**: Failed operations are retried using exponential backoff schedules.

---

## Section 15: Gmail Mailbox Integration

- Syncs mailbox metadata using authorized Google API scopes.
- Analyzes incoming email bodies and triggers asynchronous scans for new attachments.

---

## Section 16: Threat Intelligence Fusion

- Correlates hashes, IP addresses, and URLs with external feeds (VirusTotal, AbuseIPDB, URLhaus).
- Applies trust confidence weights to resolve conflicts between threat intel feeds.

---

## Section 17: OCR Ingestion Pipeline

- Extracts images from attachments.
- Processes text using Tesseract OCR, identifies malicious keywords, and extracts embedded URLs.

---

## Section 18: Complaint & Evidence Generation

- Assembles headers, body structures, and threat indicators into zip archives.
- Generates PDF cybercrime reports.

---

## Section 19: Middlewares

- **ContentLengthLimitMiddleware**: Rejects payloads exceeding 10MB (`HTTP 413`).
- **CORSMiddleware**: Whitelists specific client domains.
- **LoggingMiddleware**: Standardizes JSON console logs format.

---

## Section 20: Exception Handling

Global handlers intercept exceptions, returning standard error structures:
```python
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "error_code": "HTTP_ERROR"}
    )
```

---

## Section 21: Security Hardening

- Strictly enforces OWASP API Security Top 10 recommendations.
- Validates all inbound paths to prevent SQL or NoSQL injections.
- Encrypts PII fields at rest.

---

## Section 22: Performance Benchmarks

- Average API response time must remain under 50ms.
- Connection pooling is configured to optimize database socket reutilization.

---

## Section 23: Monitoring

- Prometheus scrapers capture API counters and queue metrics.
- OpenTelemetry tracers propagate trace IDs throughout backend endpoints.

---

## Section 24: Testing

- Pytest suites verify route responses and negative behaviors bounds.
- CI/CD workflows run static code analyzers (Bandit, Safety) on every commit.

---

## Section 25: Architectural Decision Records (ADRs)

### ADR-03: FastAPI over Django/Flask
* **Decision**: Adopt FastAPI.
* **Trade-off**: FastAPI supports native asynchronous execution, automatic Swagger generation, and fast serialization using Pydantic, which significantly improves developer velocity and performance.
