# Threat Intelligence & Adversary Intelligence Operations (E11.7)

This document details the architecture, design, and validation controls for **E11.7 — Threat Intelligence & Adversary Intelligence Operations**, extending the foundational E4 layer.

---

## 1. Architectural Overview

The threat intelligence operations subsystem enforces strict validation, security, and optimization controls for Indicator of Compromise (IOC) processing. It is composed of the following layers:

```
[ Ingested IOC ] ──► [ Ingestion Validation ] ──► [ Centralized Normalizer ] ──► [ Indexed MongoDB Lookup ]
                                                                                           │
                                                                                           ▼
                                                                                   [ Threat Match ]
```

---

## 2. IOC Validation & Normalization

Strict regex and type validations are applied at ingestion bounds, routing through `ThreatIntelService.validate_indicator` and `ThreatIntelService.normalize_indicator_value`.

### Supported IOC Types
*   **IP**: Standardized via python's `ipaddress` library. Validates both IPv4 and IPv6 structures.
*   **Domain**: Evaluated against label bounds (max 63 chars), total length (max 253 chars), and hostname rules (RFC-compliant regex). Punycode representation is supported.
*   **URL**: Schemes are strictly capped to `http` and `https`. Netloc and structure validation are enforced.
*   **File Hash**: Matches exact hex strings for MD5 (32 characters), SHA-1 (40 characters), and SHA-256 (64 characters).
*   **Email**: Regex validation matching standard address structures.

### Centralized Normalizer
Values are normalized to ensure canonical database entries:
*   *Domains/Hostnames*: Lowercased, stripped, and trailing dot removed.
*   *Emails*: Lowercased and whitespace trimmed.
*   *Hashes*: Lowercased.
*   *URLs*: Scheme and domain portion lowercased, path casing preserved.

---

## 3. SSRF (Server-Side Request Forgery) Threat Model

To mitigate SSRF risks during short URL expansions, the HTTP connector implements a strict IP resolution blocklist.

### Prohibited Subnets
Connections are blocked if the target resolves to any of the following:
*   Loopbacks: `127.0.0.0/8`, `::1`
*   Private IPv4: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
*   Link-Local: `169.254.0.0/16`, `fe80::/10`
*   Multicast: `224.0.0.0/4`, `ff00::/8`
*   Unspecified/Localhost addresses.

### Resolution & Redirect Checks
SSRF protection resolves hostnames *before* initiating connections and validates each subsequent hop in a redirect chain:

```
Target URL ──► Parse Scheme ──► Resolve DNS ──► Verify IPs (No Private/Loopbacks) ──► Connect
                                                                                        │
                                                                                        ▼
                                                                               Redirect? ──► Repeat Loop
```

Redirect chains are strictly capped at **max 5 hops** to prevent redirect loop attacks.

---

## 4. Expiration Sweep Lifecycle (TTL)

Active indicators configured with an `expires_at` date are reclaimed by a daily Celery task:
*   **Task**: `tasks.sweep_expired_indicators_task`
*   **Beat Cron Schedule**: Daily (`86400.0` second schedule interval).
*   **State transition**: Switches status from `ACTIVE` to `EXPIRED`.
*   **Auditing**: Creates audit log events for historical compliance tracking.

---

## 5. Ingestion & Index Optimizations

To optimize live detection queries, the `threat_indicators` collection has a compound MongoDB index:
*   **Target Fields**: `{"normalized_value": 1, "indicator_type": 1, "status": 1, "organization_id": 1}`

This index ensures all downstream matches (ingestion pipelines, hunting matches, and campaigns graphs) utilize high-speed covered queries.

---

## 6. Security & RBAC Policies

*   **Multi-Tenancy**: The database query explicitly filters by current `organization_id` or `None` (global system indicators), ensuring Org A cannot query or fetch Org B indicators.
*   **RBAC Permissions**: Reuse E2 baseline permissions:
    *   `threat_intelligence.read`: view IOC lists, feeds, and campaign graphs.
    *   `threat_intelligence.create`: ingest new threat indicators.
    *   `threat_intelligence.manage`: configure threat feeds and update campaigns.
*   **Audit Logging**: The following actions are logged:
    *   `THREAT_INDICATOR_EXPIRED`: Created when the sweep task expires an IOC.

---

## 7. Known Limitations

*   **Punycode Resolution**: Domains using Unicode Unicode lookalikes are matched only on Punycode or normalized forms, not in-memory visual matches.
*   **Dynamic DNS Rebinding**: Extremely short DNS TTL values could theoretically allow rebinding between initial resolution and HTTP connect. Standard socket timeout parameters mitigates this window.
