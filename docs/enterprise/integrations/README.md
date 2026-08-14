# Security Platform Integrations Architecture (Workstream E8)

This reference outlines the integration adapter design, event delivery mechanisms, secure webhook handshakes, and SSRF loopback network protections.

---

## 1. System Integration Gateway Flow

```
                      Security Pipeline
                             │
                             ▼
                    Integration Service
                             │
            ┌────────────────┴────────────────┐
            ▼                                 ▼
      SSRF URL Filter                 Canonical Normalizer
            │                                 │
            └────────────────┬────────────────┘
                             ▼
                     Integration Event
                             │
                             ▼
                    Integration Adapter
                             │
             ┌───────────────┼───────────────┐
             ▼               ▼               ▼
        SIEM Adapter    Jira Adapter    ServiceNow
             │               │               │
             └───────────────┼───────────────┘
                             ▼
                    External Platform
```

---

## 2. Inbound Webhook Signature Checks
Inbound webhooks (e.g. from ServiceNow ticketing callbacks) are validated to prevent spoofing or replay tampering:
- **HMAC Signature**: Validates signatures passed in HTTP headers (e.g. `X-Signature`) using SHA-256 and matched configuration secrets.
- **Payload Verification**: Enforces signature checks on raw request bytes payloads before parsing JSON inputs.

---

## 3. Server-Side Request Forgery (SSRF) Protection
To secure the enterprise application against internal server targeting, all outbound requests pass through a safe URL validator:
- **DNS Resolution**: Resolves hostnames to their full IP lists using local socket resolution.
- **CIDR Address Blocks**: Automatically rejects any targets pointing to loopback addresses (`127.0.0.1`, `::1`), link-local nodes (`169.254.169.254`), multicast ranges, or private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
