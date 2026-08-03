# Enterprise Technology Stack Specification: GuardianMail AI

---

## Section 1: Technology Selection Philosophy

GuardianMail AI evaluates technologies using a structured framework to ensure long-term maintainability, high availability, and operational safety:
1. **Security-First Integration**: Dependencies must support Least Privilege access, secure cryptography (e.g., bcrypt for hashing), and clean context isolation.
2. **Performance under Concurrency**: Technologies must support non-blocking asynchronous operations to handle high-volume mail queues.
3. **Decoupled Architecture**: Systems are designed around stateless APIs, asynchronous task workers, and persistent stores to facilitate horizontal scaling.
4. **Developer Experience & Standard Tooling**: We prioritize well-documented, standard tools (such as Pytest, Vite, and Terraform) to reduce onboarding friction and simplify maintenance.

---

## Section 2: Programming Languages

### Python (v3.10+)
- **Use Case**: Core FastAPI services, Celery task runners, and AI threat engines.
- **Rationale**: Python provides an extensive library ecosystem for natural language parsing, network operations, and asynchronous database adapters (such as Motor).
- **Standards**: Strictly follows PEP-8 styling formatting and utilizes static type hints.

### TypeScript (v5+)
- **Use Case**: Frontend React dashboard application.
- **Rationale**: Statically checks type safety during build compilation, preventing runtime null pointers or property access errors.
- **Standards**: Strictly follows ESLint rules and folder structural components segregation.

### Supporting Formats
- **JSON**: Data serialization for API payloads and configuration files.
- **YAML**: Infrastructure orchestration and GitHub Actions CI/CD pipelines.
- **Markdown**: Code manual files and operational playbooks.
- **Shell / PowerShell**: Backup cron triggers and dev environment bootstrapping scripts.

---

## Section 3: Backend Technology Stack

### FastAPI & Uvicorn
- **Architecture**: Asynchronous ASGI routing web server.
- **Responsibilities**: Validating inbound payloads, verifying JWT tokens, and delegating background scans.
- **Enterprise Best Practice**: Utilize Dependency Injection dependencies to manage database handles and configurations.

### Pydantic (v2+)
- **Architecture**: Data validation schemas mapping.
- **Responsibilities**: Enforcing types safety on incoming payloads before reaching DB layer.

### Celery & Redis
- **Architecture**: Distributed task workers queue.
- **Responsibilities**: Offloading Tesseract OCR extractions and heavy semantic evaluations from the main request threads.
- **Enterprise Best Practice**: Run tasks within isolated queue zones, checking execution duration metrics.

---

## Section 4: Frontend Technology Stack

### React & TailwindCSS
- **Purpose**: Fast Single Page Application (SPA) dashboard layout.
- **Architecture**: Modular component structure separated into functional units (`api/`, `components/`, `pages/`).
- **State Management**: Zustand manages local dashboard parameters; TanStack Query orchestrates API caching.
- **Enterprise Best Practice**: Avoid raw inline styling rules; configure reusable theme utility tokens.

---

## Section 5: Database Technologies

### MongoDB Atlas
- **Rationale**: A document-based database supports schema flexibility, allowing incident reports and email threat metadata to be stored in unified collections without schema migration overhead.
- **Performance Configuration**: Compound indices mapped on `(user_id_1, date_-1)` and TTL indexes configured to auto-evict logs older than 30 days.

### Redis Cache
- **Rationale**: In-memory store supporting fast user session checks and JWT token blacklisting verification.

---

## Section 6: Artificial Intelligence Stack

### Tesseract OCR
- **Use Case**: Scanning image attachments to extract text and decode obfuscated QR-code links.

### Natural Language Classifiers
- **Use Case**: Evaluating subject line semantics and email body text for urgency markers, CEO payroll impersonation patterns, and credential harvesting terminology.
- **Explainability**: The system uses explainable AI rules, translating threat vectors into clear, human-readable explanations.

---

## Section 7: Security Technologies

- **JWT Tokens**: Signed access and refresh tokens managing session validity.
- **Google OAuth2**: Single source of truth for third-party mailbox access synchronization.
- **AES-256 Gzip**: Encryption format for MongoDB dump backups scripts.
- **Secure Headers**: Custom middlewares enforcing Content-Length restrictions (cap at 10MB) and whitelisted CORS origins.

---

## Section 8: Cloud Infrastructure

- **Docker & Compose**: Containerizes proxies, APIs, databases, and monitoring services.
- **Nginx Proxies**: Gateways enforcing rate-limiting zones and SSL certificates.
- **Terraform (AWS)**: Declares IaC automation templates (VPC subnets, ALB rules, ECS Fargate services).

---

## Section 9: Development Tools

- **Code Editors**: VS Code / PyCharm.
- **API Clients**: Postman / Bruno for route testing.
- **Documentation**: Swagger UI & ReDoc generated by FastAPI.
- **Formatters**: Black (Python formatting), Isort (import sorting), and Prettier (TypeScript/CSS).

---

## Section 10: Testing Technologies

- **Pytest**: Pytest-asyncio frameworks checking route responses and negative behaviors boundaries.
- **Vitest**: Unit testing React UI dashboard elements.
- **Playwright**: End-to-end browser user journey scripts.
- **Security Checkers**: Bandit and Safety scanning code imports in CI/CD.

---

## Section 11: Monitoring Technologies

- **Prometheus & Grafana**: Scraping API metrics and visualizing dashboards.
- **Loki**: Central logging collector parsing structured JSON logs.
- **OpenTelemetry**: Distributes context spans tracing IDs throughout backend routes and workers logs.

---

## Section 12: CI/CD Technologies

- **GitHub Actions**: Automates lint testing, unit tests, and security scans on push events.
- **Semantic Versioning (SemVer)**: Enforces `MAJOR.MINOR.PATCH` increments.

---

## Section 13: Coding Standards

- **Python PEP-8**: Enforced using lint formatting checkers (Black/Ruff).
- **Type Safety**: Strictly declare type hints on all backend methods signatures.
- **React Conventions**: Keep component layouts stateless where possible; leverage hook functions.

---

## Section 14: Package Management

- **Python**: Packages managed via virtual environment configurations using requirements text files (`pip` / `requirements.txt`).
- **Frontend**: Managed via npm using package-lock tracking files (`package-lock.json`).

---

## Section 15: Performance Standards

- **Core API Latency**: < 50ms average duration.
- **Database Query target**: Mapped compound indexing lookups only (no full scan queries allowed).
- **Redis access time**: < 5ms.
- **Background jobs execution**: Asynchronous execution; Celery checks completed under 5 seconds.

---

## Section 16: Technology Decision Records (TDRs)

### TDR-01: Decoupling Task Queue using Celery & Redis
* **Decision**: Offload OCR extraction and threat intelligence lookups from FastAPI requests.
* **Alternative considered**: Running tasks synchronously inside FastAPI's background tasks.
* **Trade-off**: Increases setup complexity but prevents CPU-intensive scanning tasks from blocking incoming API requests.

---

## Section 17: Version Compatibility Matrix

| Technology | Supported Version Sizing |
| :--- | :--- |
| **Python** | `3.10.x` or `3.12.x` |
| **FastAPI** | `0.110.x` |
| **Node.js** | `20.x` (LTS) |
| **MongoDB** | `7.0.x` |
| **Redis** | `7.2.x` |
| **React** | `18.x` |

---

## Section 18: Technology Roadmap

- **Near-Term**: Migrate to MongoDB Replica Sets to support high-availability failover.
- **Long-Term**: Integrate LLM (Large Language Model) endpoints for automated generation of explainable SOC analyst summaries.
