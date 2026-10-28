# E11.8 — Security Operations Response Intelligence Documentation

This document describes the architecture, data models, state transitions, security boundary rules, scoring formulas, and testing strategies for the response intelligence layer.

---

## 1. Core Architectural Paradigm

> **CRITICAL RULE**: E11.8 recommends responses; E6 executes responses.

E11.8 does **NOT** execute active remediations, manage API credentials for third-party endpoints, or handle worker retries. It acts as the context-gathering decision engine that prepares action payloads for the SOAR engine (E6).

```
   [ Telemetry / IOC / UEBA Signals ]
                  │
                  ▼
   ┌──────────────────────────────┐
   │ E11.8 Response Intelligence  │  ◄── Evaluates risk & determines approval gates
   └──────────────┬───────────────┘
                  │ Recommended + Grounded Context
                  ▼
   ┌──────────────────────────────┐
   │      E6 SOAR Execution       │  ◄── Executes containment integrations
   └──────────────────────────────┘
```

---

## 2. ResponseDecision Data Model

Stored in MongoDB `response_decisions` collection:

*   `organization_id` (str): Tenant scoping key.
*   `incident_id` (Optional[str]): Linked incident record.
*   `campaign_id` (Optional[str]): Linked campaign record.
*   `investigation_id` (Optional[str]): Linked investigation workspace record.
*   `status` (str): `DRAFT`, `RECOMMENDED`, `PENDING_APPROVAL`, `APPROVED`, `REJECTED`, `EXPIRED`.
*   `recommended_action` (str): Controlled vocabulary action enum.
*   `severity` (str): `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
*   `approval_required` (bool): True if action requires manual analyst sign-off.
*   `risk_score` (float): Calculated risk score between 0.0 and 100.0.
*   `confidence_score` (float): Calculated recommendation confidence score between 0.0 and 100.0.
*   `decision_reason` (str): Explainable text description.
*   `evidence_refs` (List[dict]): References to original source objects (e.g. Findings, Campaigns).
*   `signal_summary` (dict): Cached metadata metrics.
*   `decision_trace` (dict): Calculation parameters (weights, normalized signals, contributions).

---

## 3. Decision Lifecycle State Machine

```
   [ DRAFT ] ──► [ RECOMMENDED / PENDING_APPROVAL ] ──► [ APPROVED / REJECTED ]
                                                   ──► [ EXPIRED ]
```

*   **DRAFT**: Initial candidate recommendation.
*   **RECOMMENDED**: Formulated low-risk actions.
*   **PENDING_APPROVAL**: Staged medium/high-risk actions waiting for analyst approval.
*   **APPROVED**: Handoff authorized.
*   **REJECTED**: Analyst rejected containment recommendation.
*   **EXPIRED**: Recommendation validity duration elapsed.

---

## 4. E11.8.2 Weighted Risk Scoring Engine

### Normalized Weights Config
*   **Detection (E11.3)**: 25%
*   **Threat Intel (E11.7)**: 25%
*   **Campaign (E11.6)**: 20%
*   **UEBA (E9)**: 15%
*   **Investigation (E11.5)**: 15%

### Formula
$$RiskScore = \sum (NormalizedSignalScore \times Weight)$$

Rounded to nearest integer (0-100).

### Severity Classification
*   `0–24`: **LOW** (Action -> `MONITOR`)
*   `25–49`: **MEDIUM** (Action -> `NOTIFY_ANALYST` / `QUARANTINE_EMAIL`)
*   `50–74`: **HIGH** (Action -> `QUARANTINE_EMAIL` / `BLOCK_INDICATOR`)
*   `75–100`: **CRITICAL** (Action -> `RESET_CREDENTIAL` / `ISOLATE_HOST`)

---

## 5. Confidence Calculation & Safety Rules

### Confidence Modifiers
*   **Corroboration Boost**: +15 if both Detection and Threat Intel risks are $\ge 70$, with an additional +10 if Campaign risk is also $\ge 70$ (max cap 100).
*   **Disagreement Penalty**: -20 if Detection risk is $\ge 70$ but Threat Intel risk is $\le 20$.

### Safety Gates
*   If **Confidence Score < 40**, any critical destructive action (like device isolation or credential reset) is automatically downgraded to **NOTIFY_ANALYST** to prevent automated false positive cascade damage.

---

## 6. Tenant Isolation & Security

*   Every repository query enforces standard tenant boundaries using `organization_id` filters.
*   Every incoming evidence signal is cross-checked against the decision's `organization_id`. Any mismatch raises a `ValueError` blocking cross-tenant contamination.
*   API endpoints require standard OAuth bearer tokens and enforce RBAC scopes:
    *   `telemetry.read` is required for listing and viewing decisions or evidence references.
    *   `telemetry.manage` is required for creating recommendations, evaluating, and patching statuses.

---

## 7. E11.8.3 Playbook Recommendation Engine

### Playbook Resolver
Resolves matching active E6 SOAR playbooks from the `soar_playbooks` database collection based on tenant scoping rules (`organization_id` boundary check) and matching `action_type`. Falls back to built-in default templates (e.g. `PLAYBOOK-EMAIL-QUARANTINE`, `PLAYBOOK-HOST-ISOLATION`) if no custom playbooks are registered.

### Evidence Sufficiency Matrix
Before recommending a playbook or high-impact action, the engine enforces evidence grounding constraints:
*   `ISOLATE_HOST` requires at least one `FINDING` or `CAMPAIGN` evidence reference.
*   `QUARANTINE_EMAIL` requires at least one `FINDING` evidence reference.
*   `BLOCK_INDICATOR` requires at least one threat intelligence `IOC` reference.
*   `RESET_CREDENTIAL` requires at least one anomalous `UEBA_SIGNAL` reference.

If required evidence is missing, the recommendation is automatically downgraded to `NOTIFY_ANALYST` (with a safety constraint explanation logged).

### Safety Downgrades
*   *Confidence Gate*: Destructive actions (Isolate, Reset, Revoke) are downgraded to `NOTIFY_ANALYST` if `confidence_score` is below 40.
*   *Missing Playbook*: Downgraded to `NOTIFY_ANALYST` if no executable playbook matches the action type.

### GRC Audit Logging
Compliance audits are logged for the following events:
*   `RESPONSE_RECOMMENDATION_CREATED`: Logged when playbook recommendation parameters are established.
*   `RESPONSE_RECOMMENDATION_DOWNGRADED`: Logged when evidence sufficiency or confidence safety limits force a downgrade.
*   `RESPONSE_PLAYBOOK_UNAVAILABLE`: Logged when no matching E6 playbook metadata can be resolved.

---

## 8. E11.8.4 Human Approval & Response Governance

### Approval Lifecycles State Machine
Strict transitions are validated on the decision document status:
*   `PENDING_APPROVAL` can transition to `APPROVED`, `REJECTED`, `EXPIRED`, or `CANCELLED`.
*   All other states (`APPROVED`, `REJECTED`, `EXPIRED`, `CANCELLED`) are terminal and cannot be transitioned back.

### separation of duties (Four-Eyes Principle)
For critical destructive containment actions (`ISOLATE_HOST`, `RESET_CREDENTIAL`, `REVOKE_SESSION`), approval requests enforce:
$$\text{Requester} \neq \text{Approver}$$
If the analyst who generated the recommendation attempts to approve the request, the transition is blocked (HTTP 403) and logged.

### Cryptographic Authorization Token
Upon successful approval, the engine generates:
1.  A secure, random validation secret key (`token_secret`).
2.  A unique token UUID (`token_id`).
3.  A SHA-256 hash of the secret (`token_hash`) stored securely in MongoDB.

The validation token is short-lived (expires after 10 minutes) and single-use only.

### Anti-Replay Consumption
*   **Validation Gate**: E6 validates that the token status is `APPROVED`, matching the decision ID, action, playbook, and version, and is not expired or consumed.
*   **Atomic Double-Spend Prevention**: Consumption atomically writes `authorization_consumed_at` to prevent any concurrent double-spending or replay attacks.

### Compliance Audits
*   `RESPONSE_APPROVAL_REQUESTED`: Logged when approval request is staged.
*   `RESPONSE_APPROVED`: Logged when request is approved.
*   `RESPONSE_REJECTED`: Logged when request is rejected.
*   `RESPONSE_APPROVAL_CANCELLED`: Logged when pending request is cancelled.
*   `RESPONSE_AUTHORIZATION_ISSUED`: Logged when token secret hash is generated.
*   `RESPONSE_AUTHORIZATION_CONSUMED`: Logged on single-use consumption.
*   `RESPONSE_AUTHORIZATION_REJECTED`: Logged when token check fails.


