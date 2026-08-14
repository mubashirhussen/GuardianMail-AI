# Threat Intelligence & Correlation Platform Reference

GuardianMail AI Enterprise Edition (v4.0) features a multi-tenant Threat Intelligence Platform (TIP) that automates the collection, normalization, scoring, correlation, and hunting of Indicators of Compromise (IOCs).

---

## 1. Threat Intelligence Architecture

The Threat Intelligence framework operates as an active pipeline spanning ingestion, data quality verification, database storage, and runtime scanner matching:

```
  External Feeds (Celery)
            │
            ▼
┌──────────────────────────────┐
│ Ingestion & Normalization   │
└───────────┬──────────────────┘
            │
            ▼
┌──────────────────────────────┐
│ Provider Enrichment & Score  │
└───────────┬──────────────────┘
            │
            ▼
┌──────────────────────────────┐
│ MongoDB Storage / Redis TTL  │
└───────────┬──────────────────┘
            │
            ▼
┌──────────────────────────────┐
│ Campaign Correlation Engine  │
└───────────┬──────────────────┘
            │
            ▼
┌──────────────────────────────┐
│  Runtime Detection Engine    │
└──────────────────────────────┘
```

---

## 2. IOC Data Model

The `ThreatIndicator` collection stores normalized threat components under strict tenant boundaries.

```json
{
  "_id": "ObjectId",
  "organization_id": "org_uuid_or_null_for_global",
  "indicator_type": "ipv4 | domain | url | file_hash | email_address",
  "indicator_value": "Malicious-Domain.com",
  "normalized_value": "malicious-domain.com",
  "first_seen": "ISODate",
  "last_seen": "ISODate",
  "confidence": 85,
  "severity": "critical | high | medium | low",
  "status": "ACTIVE | EXPIRED | REVOKED",
  "source": "VirusTotal | AlienVault",
  "tags": ["apt-29", "credential_harvesting"],
  "expires_at": "ISODate"
}
```

---

## 3. Feed Ingestion & Normalization

Feed collection is automated via cron-scheduled Celery background workers.
- **Normalization Rules**:
  - Domains/emails are downcased and stripped.
  - URLs undergo scheme normalization while preserving query paths.
- **Deduplication**: Idempotent upserts match existing values to update last-seen metrics rather than inserting duplicate records.

---

## 4. Provider Integration Adapters

We support modular interfaces to retrieve reputations on-demand:
- **VirusTotal**: Scans hashes, domains, and URLs.
- **AbuseIPDB**: Assesses IP reputations and ASN blocks.
- **URLhaus & AlienVault**: Maps malicious payloads and actor tagging.

All lookups route through standard cache handlers in Redis to enforce API query quotas.

---

## 5. Confidence Scoring Model

Compounds indicators from all sources:
- **Weights**: VirusTotal (+20), AbuseIPDB (+15), URLhaus (+25), AlienVault (+15).
- **Severity Classification**:
  - Positive matches on malware/phishing list -> `CRITICAL`.
  - Multi-source detections -> `HIGH`.
  - Single detections -> `MEDIUM`.

---

## 6. Threat Correlation & Campaigns

The correlation engine periodically scans observations. When $\ge 3$ indicators match shared infrastructure tags within a spatial timeframe, the engine auto-creates a `ThreatCampaign` linking:
- IOC nodes
- Scanned Emails (Incidents)
- Target Users

---

## 7. Security & Tenant Isolation

- **Private Intelligence**: IOCs created by Organization A are strictly invisible to Organization B (`organization_id` queries).
- **Global Intelligence**: Common public feeds are shared but restricted to read-only views for non-admin analysts.

---

## 8. Troubleshooting

- **Feeds Offline**: Ensure Redis broker and celery worker processes are running.
- **API Key Leaks**: Never hardcode credentials. Leverage setting variable hooks and encrypted MongoDB configurations.
