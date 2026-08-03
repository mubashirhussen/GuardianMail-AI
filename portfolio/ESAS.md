# Enterprise Security Architecture Specification: GuardianMail AI

---

## Section 1: Security Vision

GuardianMail AI enforces a Defense-in-Depth posture across all architectural layers, adhering to Zero-Trust principles:
- **Zero-Trust Access Model**: Never trust, always verify every authentication context, connection path, and payload.
- **Confidentiality, Integrity, and Availability**: Enforces field-level encryption for data at rest, logs audit event chains in read-only tables, and targets 99.999% gateway availability.
- **Compliance Targets**: Meets requirements for SOC 2 Type II, ISO 27001 certification, and GDPR data privacy standards.

---

## Section 2: Threat Modeling & STRIDE Analysis

The attack surface boundaries are categorized and analyzed under the STRIDE methodology:

| Threat | Description | Implemented Mitigation | Residual Risk |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Attackers impersonating known senders. | Strict SPF, DKIM, and DMARC verification. | Low |
| **Tampering** | Modification of scanned mail metadata. | Multi-document transactions and hash logs. | Low |
| **Repudiation** | Denying admin security actions. | Read-only append audit logging. | Very Low |
| **Information Leak**| Exposure of email bodies or PII. | Field-level encryption and PII scrubbers. | Low |
| **Denial of Service**| Flooding APIs with oversized payloads. | ContentLengthLimitMiddleware (max 10MB). | Low |
| **Elevation of Privilege**| Unauthorized access to SOC tools. | RBAC permission middleware checks. | Very Low |

---

## Section 3: Identity & Access Management (IAM)

- **Authentication Single Source of Truth**: Integrates Google OAuth2 for directory authentication.
- **Access Tokens**: Employs signed, short-lived JWT access tokens (15-minute expiry) and refresh tokens (7-day expiry).
- **Session Control**: Revoked tokens are instantly blacklisted in Redis caches.

---

## Section 4: Zero Trust Architecture

- **Continuous Verification**: Authenticates every API call using signature checks, session state validations, and IP rate limiting.
- **Micro-Segmentation**: Separates public Nginx entry gateways from internal Celery workers, databases, and caches in secure networks.

---

## Section 5: API Security (OWASP Top 10)

- **Injection Prevention**: Enforces Pydantic schema validation to prevent NoSQL injection.
- **Rate Limiting**: Limits requests per IP per minute using a Redis-backed sliding-window rate limiter.
- **Safe Exposure**: Sanitizes payloads to hide internal execution exceptions, returning standard error schemas.

---

## Section 6: Application Security

- **Path Traversal Protection**: Attachment upload filenames are sanitized (`sanitize_and_validate_filename`).
- **File Validation**: Rejects files with multiple extensions or executable signatures (`.exe`, `.sh`).
- **XSS Mitigation**: Encodes React outputs and restricts script execution using Content Security Policies (CSP).

---

## Section 7: Data Protection & Cryptography

- **Data at Rest**: Sensitive fields (email body, recipient PII) are encrypted in MongoDB Atlas using AES-256 field-level encryption.
- **Data in Transit**: Restricts traffic to TLS 1.3 encrypted HTTPS.
- **Password Safety**: Hashes credentials using bcrypt with a work factor of 12.

---

## Section 8: Secure Coding Standards

- **Python**: PEP-8 compliance validated by Black/Ruff. Bandit scans are integrated into GitHub Actions CI/CD pipelines to catch vulnerabilities like `eval` usage.
- **React/TypeScript**: Strict compilation checks, ESLint guidelines, and React sanitizations.

---

## Section 9: Secrets Management

- Hardcoded secrets are strictly forbidden.
- Configurations, API keys (e.g. VirusTotal keys), and DB connection strings are loaded from system environment variables.

---

## Section 10: Security Headers

Nginx gateways inject secure headers:
- `Content-Security-Policy`: Restricts script and object sources.
- `Strict-Transport-Security` (HSTS): Enforces HTTPS connections for 1 year.
- `X-Frame-Options`: Set to `DENY` to prevent clickjacking.
- `X-Content-Type-Options`: Set to `nosniff` to prevent MIME-sniffing.

---

## Section 11: Logging & Auditing

- Logs admin password modifications, role changes, and threat quarantines to read-only collections.
- Logs include standard context variables: Timestamp, Request ID, Correlation ID, Actor ID, and Client IP.

---

## Section 12: Security Monitoring

- Prometheus scrapers collect metrics on authentication failures and policy violations.
- Loki aggregates JSON logs to enable correlation, searching, and visualization.

---

## Section 13: DevSecOps Pipelines

- The GitHub Actions pipeline runs automated security checks on every code push:
  - **SAST (Bandit)**: Static code analysis for security vulnerabilities.
  - **Dependency Scanner (Safety / pip-audit)**: Identifies outdated libraries containing CVEs.

---

## Section 14: Supply Chain Security

- Generates Software Bill of Materials (SBOM) manifests for every production container release.
- Only imports dependencies from verified registries (PyPI, npm).

---

## Section 15: Cloud & Container Security

- **Non-root Execution**: The FastAPI runtime runs under `USER appuser` (UID 10001) instead of the root context.
- **Port Security**: Exposes only ports 80 and 443 at the Nginx gateway.

---

## Section 16: AI Security & Model Integrity

- **Prompt Sanitization**: Sanitizes input strings before classification to prevent LLM prompt injections.
- **Data Poisoning Protection**: Restricts retraining database updates to authorized analysts.

---

## Section 17: Compliance Matrix

- **ISO 27001**: Implements strict access controls, read-only audit logging, and documented SRE recovery runbooks.
- **GDPR**: Restricts PII exposure, encrypts data at rest, and automates user deletion requests.

---

## Section 18: Incident Response & SOAR Playbooks

- **Detection**: Flags suspicious activities (failed logins, high risk scores) in the SOC dashboard.
- **Containment**: Triggers automated playbooks to quarantine emails and block malicious sender domains.
- **Escalation SLA Matrix**:
  - **S1 Critical**: Support ticket created and paged within 15 minutes.
  - **S2 Major**: Resolution target within 4 hours.

---

## Section 19: BC & DR Objectives

- **Recovery Objectives**: RTO < 4 hours; RPO < 1 hour.
- **Failover Plan**: Three-node MongoDB replica sets distribute data globally, facilitating auto-recovery during regional failures.

---

## Section 20: Penetration Testing

- Schedule annual independent external penetration tests targeting HTTP routes and API endpoints.
- Conduct regular automated vulnerability scans (using OWASP ZAP or equivalent tools) within test environments.

---

## Section 21: Security Testing

- Unit security tests verify access control middleware, token verification errors, and size limits.
- CI pipelines execute automated security tests before release sign-off.

---

## Section 22: Architectural Decision Records (ADRs)

### ADR-06: Strict Content Length Limits at Gateway (10MB)
* **Decision**: Implement a hard payload size cap of 10MB.
* **Trade-off**: Limits the upload size of extremely large PDF/Image files, but prevents denial-of-service (DoS) attempts that try to exhaust container memory.
