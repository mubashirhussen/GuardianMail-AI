# E12.1 — Pre-Flight Audit Report

## 1. Executive Summary
This pre-flight audit scans the codebase for credentials, hardcoded keys, network port exposures, and environment configurations before starting deployment validation.

---

## 2. Hardcoded Secrets & Credentials Audit

| File Path | Secret Category | Severity | Remediation Required |
| :--- | :--- | :--- | :--- |
| `backend/app/config/settings.py` | Default secret key placeholder | **MEDIUM** | Enforced strong key requirements for production via Pydantic settings validator (already implemented). |
| `docker-compose.yml` | Hardcoded default SECRET_KEY | **MEDIUM** | In production deployments, pass SECRET_KEY dynamically using environment variables or Docker Secrets. |
| `backend/docker-compose.yml` | Hardcoded default SECRET_KEY | **MEDIUM** | Used for local development only. Do not deploy to staging or production. |

---

## 3. Network Port Exposures Audit

| Service | File Path | Current Port Exposure | Risk / Severity | Remediation Required |
| :--- | :--- | :--- | :--- | :--- |
| `mongo` | `docker-compose.yml` | `27017:27017` | **HIGH** (exposes db publicly) | Remove ports mapping from production docker-compose.yml to keep MongoDB internal to `guardianmail_net`. |
| `redis` | `docker-compose.yml` | `6379:6379` | **HIGH** (exposes redis publicly) | Remove ports mapping from production docker-compose.yml to keep Redis internal. |

---

## 4. Conclusion
Remediation of the MongoDB and Redis public port exposures in `docker-compose.yml` is required to ensure proper network isolation during deployment.
