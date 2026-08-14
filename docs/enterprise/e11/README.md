# Advanced Detections & Investigations Architecture (Workstream E11)

This reference outlines the correlation logic, attack graph construction, AI grounding citations, and E1–E10 integration points.

---

## 1. End-to-End Incident Remediation Flow

```
                      Threat Inbound Event
                               │
                               ▼
                    E4 Domain Reputation Check
                               │
                               ▼
                    E9 UEBA Anomaly Baseline
                               │
                               ▼
                   E10 Data Partition Logged
                               │
                               ▼
                   E11 Detection Rule Trigger
                               │
                               ▼
                   Case Investigation Opened
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
     Attack Graph Traversal               E5 Copilot Summary
            │                                     │
            └──────────────────┬──────────────────┘
                               ▼
                     Remediation Deploy
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
     E6 SOAR Actions                     E7 GRC Evidence Hash
            │                                     │
            └──────────────────┬──────────────────┘
                               ▼
                     E8 SIEM Log Exported
```

---

## 2. Attack Graph Traversals
To help SOC analysts identify lateral movements, E11 traverses related entities (e.g. users, IPs, domains) linked to a case:
- **Tenant Filter**: Multi-tenant controls ensure that graph generation queries are constrained to the current organization context.
- **Attribution**: Overlapping indicators overlay Campaign mappings to indicate wider campaign groupings.

---

## 3. AI Copilot Grounding (E5)
To ensure AI summaries do not hallucinate, response templates explicitly isolate:
- **Observed Facts**: Logged timeline items, actual matching evidence, and confirmed identifiers.
- **Model Inferences**: AI predictions, risk estimations, and correlation patterns.
