# GRC & Security Posture Architecture Reference (Workstream E7)

This document outlines the architecture, data models, evidence snapshot protocols, and posture rating calculations of the Governance, Risk, and Compliance (GRC) module.

---

## 1. Conceptual Posture Scoring Workflow

```
            Compliance Controls       Security Findings       Inherent Risks
                    │                        │                       │
                    ▼                        ▼                       ▼
          Control Status Penalty      Gaps Penalty      Risk Matrix Penalty
                    │                        │                       │
                    └────────────────────────┼───────────────────────┘
                                             ▼
                                    Raw Posture Score
                                             │
                                             ▼
                                  Bounded Posture Score [0 - 100]
                                             │
                                             ▼
                                  Corporate Posture Rating
                                  (Optimal / Sufficient / etc.)
```

---

## 2. Dynamic Evidence Snaps Pipeline
The automated evidence snapshot pipeline dynamically queries database tables to verify control readiness:
1. **SSO Configuration Snap**: Captures identity metadata, maps issuer settings, and generates a tamper-evident SHA-256 integrity signature stored in `compliance_evidence`.
2. **Security Policies Snap**: Checks count of active policies and stores the compiled validation hash.

---

## 3. Explaining Posture Metrics
The overall corporate posture calculation deducts from a 100.0 baseline:
- **Control Penalties**: Deducts `15 points` for each `FAIL` control, `8 points` for `PARTIAL` control, and `3 points` for `NOT_ASSESSED` control.
- **Open Findings**: Deducts `5 points` for every open security finding.
- **Critical/High Risks**: Deducts `10 points` for each critical risk and `5 points` for each high risk.

---

## 4. Compliance Disclaimers
All reporting outputs and executive dashboard widgets display a mandatory compliance warning statement:
> "This score is for internal security posture estimation and does not represent formal compliance certification."
