# E11 — Security Model: Tenant Isolation & Auditing

This document specifies the security controls mapping, permission structure, and auditing configurations for E11.1.

## 1. Authentication & RBAC (E1 & E2)
All API endpoints enforce active JWT authentication checks. Role-based actions map to:
- **`telemetry.read`**: Required to view rules, details, versions, and audits. Mapped to `admin`, `soc_analyst`, `security_analyst`.
- **`telemetry.manage`**: Required to register rules, submit edits/version updates, and trigger status lifecycle changes. Mapped to `admin`, `soc_analyst`.

## 2. Multi-Tenant Boundary Isolation
Every database query is bound by the user's `organization_id` derived from their token payload:
- Cross-tenant rule queries are blocked and return standard `404` or `400` errors.
- Version history lists and audit logs are checked at the service layer to prevent cross-tenant data leaks.

## 3. Auditing (E7)
Security-sensitive operations are captured in the `audit_logs` collection:
- `DETECTION_CREATED` (logs creator, rule name/ID)
- `DETECTION_UPDATED` (logs author, rule ID, and version number incremented)
- `DETECTION_STATUS_CHANGED` (logs transitioning status values)
- `DETECTION_STATUS_CHANGE_REJECTED` (logs unauthorized or invalid status transition attempts)
