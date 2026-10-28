# E11.8.4 — Human Approval & Response Governance

This document describes the architectural design, lifecycle, validation parameters, and APIs for response intelligence approval and governance.

---

## 1. Architectural Paradigm & E6 Boundary

```
   [ E11.8.3 Playbook Mapped Rec ]
                 │
                 ▼
   ┌─────────────────────────────┐
   │    E11.8.4 Governance       │ ◄── Enforces separation of duties & issue tokens
   └─────────────┬───────────────┘
                 │ Token Secret
                 ▼
   ┌─────────────────────────────┐
   │         E6 SOAR             │ ◄── Validates and consumes validation token
   └─────────────────────────────┘
```

The governance layer does not call external remediation APIs, execute playbooks, or retrieve credentials. E6 SOAR validates authorization token status and consumption atomically before carrying out changes.

---

## 2. Approval Lifecycle State Machine

```
                  ┌───► APPROVED (Terminal)
                  ├───► REJECTED (Terminal)
   [ PENDING_APPROVAL ]
                  ├───► EXPIRED  (Terminal)
                  └───► CANCELLED (Terminal)
```

Transitions out of terminal states are blocked and rejected with an HTTP 400 error.

---

## 3. separation of duties (Four-Eyes Principle)

For critical containment actions (`ISOLATE_HOST`, `RESET_CREDENTIAL`, `REVOKE_SESSION`), we enforce separation of duties:
$$\text{Requester} \neq \text{Approver}$$
If the analyst who requested approval or created the recommendation attempts to approve it, the request is rejected with an HTTP 403 Forbidden.

---

## 4. Cryptographic Validation & Replay Prevention

Upon approval, the service:
1.  Generates a cryptographically secure token secret (`token_secret`) and unique UUID (`token_id`).
2.  Stores a SHA-256 hash of the secret (`token_hash`) in MongoDB.
3.  Implements atomic compare-and-swap update filters to flag consumption:
    *   Set `authorization_consumed_at` to the current time if it was previously `None`. This blocks concurrent double-spending or token reuse.
    *   Rejects requests if the token has expired (10 minutes lifetime).

---

## 5. REST API Inventory

| Method | Endpoint | Description | Scope |
| :--- | :--- | :--- | :--- |
| **POST** | `/api/v1/response-intelligence/decisions/{id}/approval` | Requests human approval, status PENDING_APPROVAL | `response.manage` |
| **GET** | `/api/v1/response-intelligence/decisions/{id}/approval` | Retrieves non-sensitive request parameters | `response.read` |
| **POST** | `/api/v1/response-intelligence/decisions/{id}/approval/approve` | Approves request and issues cryptographic token | `response.approve` |
| **POST** | `/api/v1/response-intelligence/decisions/{id}/approval/reject` | Rejects request with analyst reason | `response.reject` |
| **POST** | `/api/v1/response-intelligence/decisions/{id}/approval/cancel` | Cancels pending request | `response.manage` |
| **POST** | `/api/v1/response-intelligence/authorizations/validate` | Validates token parameters and validity | `response.read` |
| **POST** | `/api/v1/response-intelligence/authorizations/consume` | Atomically consumes token to prevent replay | `response.manage` |

---

## 6. Audit Logging Matrix

Every governance step records compliant records:
*   `RESPONSE_APPROVAL_REQUESTED`
*   `RESPONSE_APPROVED`
*   `RESPONSE_REJECTED`
*   `RESPONSE_APPROVAL_CANCELLED`
*   `RESPONSE_APPROVAL_EXPIRED`
*   `RESPONSE_AUTHORIZATION_ISSUED`
*   `RESPONSE_AUTHORIZATION_CONSUMED`
*   `RESPONSE_AUTHORIZATION_REJECTED`
*   `RESPONSE_APPROVAL_TRANSITION_REJECTED`
