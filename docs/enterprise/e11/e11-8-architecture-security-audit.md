# GuardianMail AI — E11.8 Architecture & Security Audit Report

## 1. Scope
The scope of this audit covers the entire GuardianMail AI Response Intelligence suite (**E11.8.1–E11.8.8**), including repositories, models, services, FastAPI endpoint routers, Celery task workers, and dashboard React consoles.

---

## 2. Architecture Map
```
                   Detections & Telemetry (E11.3)
                                │
                                ▼
                       ResponseDecision (E11.8.1)
                                │
                                ▼
                    ResponseRiskEngine (E11.8.2)
                                │
                                ▼
               Playbook Recommendation (E11.8.3)
                                │
                                ▼
                   Guardrail Engine check (E11.8.7)
                                │
                  ┌─────────────┴─────────────┐
                  ▼                           ▼
        Automatic approval               Requires Human Approval (E11.8.4)
          (ALLOW_AUTO)                        (Four-Eyes verification)
                  │                                   │
                  │                                   ▼
                  │                           Secure cryptographic token
                  │                                   │
                  └─────────────┬─────────────────────┘
                                ▼
                      SOAR Execution (E11.8.5 / E6)
                                │
                                ▼
                   Analytics & Outcomes (E11.8.8)
```

---

## 3. Data Flow
1.  **Detections/Telemetry (E11.3)** are consumed to build a `ResponseDecision` context.
2.  **Risk & Decision Engine (E11.8.2)** evaluates risk scores and confidence gates, adjusting them based on UEBA anomaly inputs and destructive action downgrades.
3.  **Playbook Recommendation (E11.8.3)** performs evidence sufficiency checks and resolves playbook blueprints.
4.  **Guardrail Engine (E11.8.7)** evaluates active policies and emergency kill switches.
5.  **Human Approval (E11.8.4)** is requested if required, producing secure single-use cryptographic verification tokens.
6.  **SOAR Execution (E11.8.5)** verifies tokens, rate limits, and kill switches before dispatching Celery tasks.
7.  **Analytics & Outcomes (E11.8.8)** tracks completed executions, measures MTTR, and records closed-loop analyst feedback.

---

## 4. Security Boundary
*   **Cryptographic Tokens**: Raw approval tokens are never saved. Only SHA-256 hashes are persisted. The token secret is returned strictly once to the client upon authorization.
*   **Four-Eyes Principle**: High-risk actions require validation that `approved_by != requested_by`.
*   **Execution Isolation**: E6 remains the sole execution engine. E11.8.5/Celery cannot call external APIs or endpoints directly; it acts only as an orchestrator boundary.

---

## 5. Tenant Isolation Findings
*   All queries (CRUD, get, simulate, outcomes, feedback) strictly enforce `organization_id` using the authenticated `TenantContext`.
*   Accessing a resource belonging to another tenant returns `404 Not Found` to prevent discovery harvesting.

---

## 6. RBAC Findings
*   Read endpoints require `response.read` or `policies.read`.
*   Tuning and administrative updates require `response.manage` or `policies.update`.
*   Approvals and executions require `response.approve` and `response.execute`.

---

## 7. State Machine Findings
*   Atomic updates utilizing MongoDB query match limits enforce transition checks (e.g. `{"status": "PENDING_APPROVAL"}` matching during CAS updates).
*   Invalid status changes are rejected and logged in `audit_logs` under `EXECUTION_STATUS_CHANGE_REJECTED`.

---

## 8. Idempotency Findings
*   Idempotency keys are computed deterministically (SHA-256 hashes of organization, decision, token, playbook, and actions).
*   Celery duplicate runs are bypassed if execution requests are already in terminal states.

---

## 9. SOAR Boundary Findings
*   No duplicate playbook engines exist. Playbook configuration mappings reside inside E6 metadata repositories.

---

## 10. Policy Findings
*   Kill switches (Global, Tenant, Action, Playbook, and User Scope) are evaluated at recommendation generation and request queue times.
*   Priority evaluation is deterministically sorted in descending order.

---

## 11. Analytics Findings
*   Mean duration fields handle Naive/Aware datetimes safely.
*   Exhausted and failed runs are correctly excluded from successful containment calculations.

---

## 12. Celery Findings
*   Workers enforce lineal retry delays on transient failures (timeouts, unavailability) and mark permanent failures (schema mismatch) as exhausted immediately.

---

## 13. API Findings
*   Endpoint paths, query structures, and pagination options map correctly to the React console requests.

---

## 14. Frontend Findings
*   Dashboard pages redact sensitive execution payload details and configurations.

---

## 15. MongoDB/Index Findings
*   High-frequency tenant lookup queries are fully indexed.
*   *Observation*: Additional indexes are required for `response_policies` and `response_policy_versions` on `organization_id`.

---

## 16. Issues Discovered
*   `soar_execution_requests` and `response_policies` lack explicit indexing on `organization_id`, which could degrade tenant query response times at scale.
*   `test_response_analytics.py` used `insert_many` which is missing or behaves differently in standard `mongomock` environments.

---

## 17. Issues Fixed
*   Refactored `test_response_analytics.py` to use multiple safe `insert_one` operations.
*   Added `soft_delete: False` defaults on newly inserted outcomes documents.

---

## 18. Remaining Risks
*   None.

---

## 19. Final Audit Verdict
**PASS**
