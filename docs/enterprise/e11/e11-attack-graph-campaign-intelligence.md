# E11.6 — Attack Graph & Campaign Intelligence

This document specifies the architecture, data models, and services for the **Attack Graph Generation** and **Campaign Intelligence Correlation Engine** introduced in Workstream E11.6.

---

## 1. Overview & Architecture

E11.6 answers two critical questions for SOC analysts:
1. **"How do security entities and incidents link together to form a structured attack path?"** (Resolved via `AttackGraphService`)
2. **"Which incidents belong to the same overarching threat actor campaign?"** (Resolved via `CampaignService`)

### High-Level Components

```
                E10 Security Data Platform
                            │
                            ▼
               ┌─────────────────────────┐
               │  E11.6 Campaign Engine  │
               └────────────┬────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        ▼                                       ▼
┌──────────────┐                        ┌──────────────┐
│ Query Builder│                        │  Scoring     │
│ & Traversal  │                        │  Engine      │
└───────┬──────┘                        └───────┬──────┘
        │                                       │
        ├─► E4 Threat Intelligence              ├─► Shared IOC (+40)
        ├─► E9 UEBA Anomalies                   ├─► Shared Technique (+20)
        └─► E11.3 Detection Rules               ├─► Shared Entity (+15)
                                                └─► Temporal Prox (+10)
```

---

## 2. Attack Graph Engine

The attack graph traversal dynamically constructs a directed node-link graph from active workspace evidence and relationships.

### Traversal Algorithm & Recursion Safe Guards
* **Depth Limitation**: Standard traversal max-depth is capped at `3` (customizable up to `5`).
* **Graph Size Safety**: Graph expansion aborts if node count exceeds `250` or edge count exceeds `500` to protect browser rendering performance.
* **Cycle Tracking**: Uses a visited set of nodes `visited_nodes` to prevent infinite loops in cyclic dependencies.

### Integrated Enrichment
* **E4 Threat Intel**: Enriches IP, Domain, and URL nodes with severity status and reputation metadata from threat feeds.
* **E9 UEBA**: Enriches User nodes with real-time risk scores and anomaly indicators.
* **MITRE ATT&CK**: Enriches Detection and Finding nodes with active ATT&CK techniques (e.g. T1566 Phishing) and mitigations.

---

## 3. Campaign Correlation Scans

The scanner chronologically inspects recent open incidents and correlates them into Suspected campaigns based on the following weighted factor signals:

| Signal Factor | Trigger Condition | Weight Value |
| :--- | :--- | :--- |
| **Shared IOC** | Incidents share identical malicious IP, Domain, or URL. | **+40** |
| **Shared Technique** | Incidents trigger same MITRE ATT&CK technique IDs. | **+20** |
| **Shared Entity** | Incidents link to the same User or Device credentials. | **+15** |
| **Temporal Proximity** | Incidents occurred within a 48-hour active window. | **+10** |

*Campaign Candidate threshold is set at a cumulative score of `50` to group them under "Suspected" for analyst case review.*

---

## 4. Multi-Tenant Boundaries & Privacy
* **Rule**: Under no circumstances can Organization A view, query, or traverse nodes belonging to Organization B.
* **Implementation**: Every repository fetch, Celery task scanner, and REST API controller filters by `context.organization_id` resolving from user identity validation token.

---

## 5. REST APIs

### Investigations Graph
* `GET /api/v1/investigations/{id}/graph`
  * Retrieves node-link schema.
  * Parameters: `max_depth` (default 2).

### Campaigns Workspace
* `GET /api/v1/campaigns` - List active campaigns.
* `POST /api/v1/campaigns` - Manual campaign case creation.
* `GET /api/v1/campaigns/{id}` - Campaign details workspace.
* `PUT /api/v1/campaigns/{id}` - Transition state (`SUSPECTED` -> `CONFIRMED` etc.).
* `POST /api/v1/campaigns/{id}/notes` - Log analyst updates.
* `POST /api/v1/campaigns/scan` - Trigger Celery background scan.

---

## 6. Unit Testing & Verification

The Pytest suite in `tests/test_campaigns_graph.py` validates the following:
1. **test_attack_graph_construction_and_enrichment**: Confirms traversal fetches correct nodes and enriches them with E4 and E9 indicators.
2. **test_attack_graph_cycle_protection**: Assures cycles are caught and terminated without infinite recursion.
3. **test_campaign_crud_and_status_validation**: Validates manual CRUD state rules and status transition errors.
4. **test_campaign_correlation_scanner**: Confirms multi-signal rules correctly calculate score factors and register suspected campaigns.
5. **test_campaigns_and_graph_multi_tenant_isolation**: Enforces organization-based access boundaries.
