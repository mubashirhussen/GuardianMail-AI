# E11 — Detection Engineering Lifecycle & Versioning

This document outlines the rule schemas, immutable versioning strategy, and lifecycle transitions enforced by the E11.1 platform.

## 1. Lifecycle State Machine
Detections progress through an explicit, validated state transition hierarchy:

```text
DRAFT
  ↓
TESTING
  ↓
REVIEW
  ↓
ACTIVE
  ↓
DISABLED
  ↓
DEPRECATED
  ↓
RETIRED
```

- **Valid Transitions**: Only configured pathways (e.g. `DRAFT` to `TESTING`) are permitted.
- **Enforcement**: Any illegal transition (such as `RETIRED` to `ACTIVE` or `DRAFT` to `ACTIVE` directly) is rejected at the API layer and logged in the organization's security audit logs.

## 2. Immutable Versioning
To prevent silent modifications to active detections, rules utilize a git-like versioning strategy:
- Every creation registers **Version 1** in the `detection_versions` collection.
- Every update to rule parameters (name, description, conditions, etc.) creates a new document incrementing the version index (e.g., Version 2) and records the change comments.
- Active detections point to their latest version, keeping previous configurations preserved.
