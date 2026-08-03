# Developer Experience & Documentation Specification: GuardianMail AI

---

## Section 1: Developer Experience Vision

GuardianMail AI treats developer experience (DevEx) and technical documentation as first-class product elements, adhering to a "Docs-as-Code" methodology:
- **Onboarding Goal**: Enable a newly joined engineer to spin up a fully functioning local environment and submit their first pull request within their first day.
- **Self-Service Engineering**: Standardizes CLI scripts, development configurations, and pre-commit checks to minimize local friction.
- **Consistent Quality**: Enforces strict formatters, linter validations, and automated API generation routines.

---

## Section 2: Repository Organization & Governance

The project is managed within a monorepo structure:
- `/backend`: Core FastAPI routes, threat engines, database layer, and celery tasks.
- `/frontend`: React dashboard application and Vite configuration.
- `/infrastructure`: Terraform configuration files and Docker orchestration scripts.
- `/portfolio`: Architecture specifications, operational manuals, and project specs.
- `/scripts`: Shell tools to automate local setups and backup restorations.
- **Branch Protection**: Master and main branches are protected, requiring peer reviews and clean CI pipeline runs before merge.

---

## Section 3: Local Setup & Troubleshooting

### Prerequisites
- **Python**: v3.10+ (v3.12 recommended).
- **Node.js**: v20+ (LTS).
- **Docker & Compose**: Desktop or CLI tooling.

### Bootstrapping Environment
1. Copy the environment variables:
   ```bash
   cp .env.example .env
   ```
2. Start the local Compose stack:
   ```bash
   docker-compose up --build
   ```
3. Verify backend liveness:
   ```bash
   curl http://localhost:8000/api/v1/health/live
   ```

### Troubleshooting FAQ
* **Celery task execution timeout**: Ensure local Redis is running on port `6379` and reachable by the worker containers.
* **Vitest runtime import error**: Re-install dependencies using `npm ci` before running tests.

---

## Section 4: Coding Standards & Formatting

- **Python (FastAPI)**: Formatted via `Black` (PEP-8) and import-sorted using `isort`. Static type hints must be declared on all parameters.
- **TypeScript (React)**: Standardized using Prettier and checked via ESLint rules.

---

## Section 5: Git & Commit Messages Strategy

- **Branch Naming**: Feature branches follow the `feature/{issue-id}-{name}` format; bugfixes follow the `bugfix/{issue-id}-{name}` format.
- **Conventional Commits**: Commit messages must follow the standard conventional commits structure:
  - `feat(auth): add MFA challenge validation route`
  - `fix(scanner): sanitize path characters in uploads`

---

## Section 6: Code Review Checklist

Reviewers must verify changes against three core criteria:
1. **Security**: Validate that endpoints enforce RBAC access restrictions, sanitize path parameters, and mask sensitive PII fields.
2. **Performance**: Verify that MongoDB queries leverage compound indexes and do not trigger full collection scans.
3. **Tests**: Ensure new code changes are covered by unit or integration tests.

---

## Section 7: API Documentation

- FastAPI automatically generates OpenAPI schemas and exposes them via Swagger UI at `/docs`.
- Endpoint parameters are documented using docstrings, which are automatically parsed into ReDoc.
- Standardized error codes are returned in the response payload.

---

## Section 8: SDK & Client Guidelines

Clients consuming the APIs must implement:
- **Rate Limit Retries**: Handle HTTP `429 Too Many Requests` responses using exponential backoff retry schedules.
- **Cursor-Based Pagination**: Paginated endpoints use cursor queries instead of offset models.

---

## Section 9: Architecture Decision Records (ADRs)

- Architecture decisions are recorded using the standard ADR template (`ADR-XX.md`).
- ADRs document the date of decision, the context, proposed options, trade-offs, and final decisions.

---

## Section 10: Recommended Developer Tooling

- **IDE**: VS Code (recommends setting up auto-save formatting hooks) or PyCharm.
- **Client Workspace**: Postman or Bruno.
- **CLI**: GitHub CLI for pull request management.

---

## Section 11: Knowledge Base & Onboarding Runbooks

Onboarding runbooks describe the system architecture, how the frontend communicates with the backend APIs, and how Celery workers consume task payloads from Redis brokers.

---

## Section 12: Documentation Guidelines

- **Markdown Standards**: Documents must use standard GitHub-Flavored Markdown.
- **Diagrams**: Process flows and system integrations are visualized using Mermaid blocks within documents.

---

## Section 13: Webhooks & Plugin Architecture

Third-party integrations use webhooks. The webhook service signs event payloads with secret keys, allowing receivers to verify payload integrity using SHA-256 signatures.

---

## Section 14: Engineering Productivity Tools

- Pre-commit hooks run Black, isort, and ESLint checks on every commit, preventing malformed commits from being pushed.
- Verification scripts (`verify_integration.py`, `verify_performance.py`) enable developers to test their changes locally before submitting a PR.

---

## Section 15: Contribution Workflows

1. Fork the repository and create a branch from `main`.
2. Implement your changes, verifying formatting and running tests locally.
3. Open a PR, complete the checks listed in the pull request template, and assign reviewers.

---

## Section 16: API Versioning Policy

- Route versioning uses URL segments (e.g. `/api/v1/`).
- Breaking changes require a version bump (e.g. migrating to `/api/v2/`), keeping v1 endpoints active until the deprecation period expires.

---

## Section 17: Documentation Automation

- CI pipelines automatically validate OpenAPI schemas, generate code documentation, and verify markdown links.
- Conventional commits are parsed to automatically generate release notes and changelogs.

---

## Section 18: Engineering Metrics

We track engineering productivity metrics:
- **Build Time**: CI/CD runs should execute in under 10 minutes.
- **Change Lead Time**: Measure the duration from code check-in to production deployment.

---

## Section 19: Architectural Decision Records (ADRs)

### ADR-09: Docs-as-Code in Markdown Format
* **Decision**: Store all documentation as Markdown files directly in the repository.
* **Trade-off**: Requires developers to maintain files manually, but ensures that specifications are version-controlled alongside code changes and easily reviewed during PRs.
