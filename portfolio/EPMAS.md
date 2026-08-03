# Enterprise Platform & Multi-Tenant Architecture Specification: GuardianMail AI

---

## Section 1: Enterprise Vision

GuardianMail AI operates as an enterprise-grade Software as a Service (SaaS) platform, providing multi-tenant security operations to shield corporate domains from email-based attacks:
- **Product Strategy**: Designed for mid-market and Fortune 500 enterprises, providing API-based threat containment and security orchestration.
- **Security & Compliance Objectives**: Zero trust networks boundaries, SOC 2 Type II assurance models, and GDPR data processor alignments.
- **Scalability Target**: Scale horizontally to support over 10,000 active enterprise organizations.

---

## Section 2: Multi-Tenant Architecture

- **Tenant Hierarchy**:
  - `Root Provider`: SaaS Platform Operator control zone.
  - `Organization (Tenant)`: Mapped company unit boundary holding dedicated configuration scopes.
  - `Workspace`: Sub-entities representing departments, geographical divisions, or workspaces.
- **Tenant Isolation**:
  - *Logical Isolation*: Database documents contain an `organization_id` field. Database query operations globally enforce this filter.
  - *Physical Isolation (Enterprise Tier)*: Dedicated MongoDB databases and Celery worker queues can be provisioned for high-priority tenants.

---

## Section 3: Identity & Access Management (IAM)

- **Platform Roles**:
  - `Organization Admin`: Modifies settings, manages directory integrations, and assigns analyst roles.
  - `SOC Manager / Analyst (L2/L1)`: Triages incidents, explores threats, and executes playbooks.
  - `Compliance Officer`: Generates audit reports and compliance posture dashboards.
  - `External Auditor`: Read-only access to audit logs.
- **RBAC**: Handled by FastAPI dependencies and route middleware checks.

---

## Section 4: Enterprise Administration Portal

- **Organization Onboarding**: Provisions configuration keys, links Google OAuth directory parameters, and initializes default alert rules.
- **Workspace Management**: Configures regional sub-workspaces, allocating distinct target mailboxes for analysis.
- **Global Settings**: Enforces organization-wide policies, such as JWT session timeouts.

---

## Section 5: SOC Operations Center

- **Incident Triaging Queue**: Aggregates anomalies, groups alerts, and maps incidents to standard priority categories (S1-S4).
- **Threat Timeline**: Chronologically visualizes detected indicators (e.g. invalid DKIM signature → urgent BEC text → phishing URL payload).
- **MITRE ATT&CK Mapping**: Correlates alerts to MITRE tactics (Phishing: T1566, User Execution: T1204).

---

## Section 6: SOAR Playbook Automation

- **Automated Actions**: Quarantine flagged emails, block sender domains, or notify recipients.
- **Enrichment Integration**: Automatically queries IP and domain reputations (AbuseIPDB, VirusTotal) for detected indicators.
- **Escalation Rules**: Escalates unresolved S1 incidents to the on-call pager if no analyst claims the case within 15 minutes.

---

## Section 7: XDR Integration Readiness

- **Signal Correlation**: Prepares structures to export email logs in standard formats (CEF / Syslog) to SIEM and XDR collectors.
- **Signals Alignment**: Mapped logs correlate host alerts with corresponding email delivery timestamps.

---

## Section 8: Threat Hunting Workspace

- **Wildcard Search Query**: Enables analysts to search the metadata store for specific keywords, subject patterns, or domains.
- **Campaign Explorer**: Clusters incident reports by common variables (sender IP, payload hash, subject lines) to identify coordinated phishing campaigns.

---

## Section 9: Evidence & Chain of Custody

- **Evidence Package**: Generates compressed zip files containing raw email headers, attachment hashes, screenshots, and OCR outputs.
- **Integrity Verification**: Generates SHA-256 checksums on creation, saving hashes to read-only audit databases.
- **Download Registry**: Logs all evidence downloads (requesting user, IP address, timestamp) to satisfy forensic requirements.

---

## Section 10: Incident Response Management

- **Priority Matrix**:
  - **S1 Critical**: Multiple BEC reports from executive mailboxes. Action: Auto-quarantine.
  - **S2 Major**: High-risk attachment containing macro code. Action: Analyst triage.
- **Resolution Tracking**: Records incident logs from creation to containment, including details on containment actions taken.

---

## Section 11: Compliance Management

- **SOC 2 Type II**: Enforces multi-factor authentication, read-only audit logging, and logical tenant isolation.
- **GDPR**: Restricts PII exposure, encrypts data at rest, and provides automated deletion scripts.

---

## Section 12: Enterprise Reporting

- **Executive Summary**: Generates PDF reports tracking threat trends, block rates, and the organization's overall risk score.
- **Board-Ready Dashboards**: Displays charts detailing security ROI, avoided risks, and incident resolution times.

---

## Section 13: Customer Success & Health Metrics

- **Organization Health Score**: Calculates a security score (0-100) based on SPF/DKIM/DMARC configurations and analyst response times.
- **Recommendations**: Proposes steps to improve security posture (e.g., "Enable DMARC Reject policy").

---

## Section 14: Billing & Subscription Tiers

- **Tiers**:
  - `Professional`: Up to 100 users, standard scanners.
  - `Enterprise`: Unlimited users, dedicated Celery queues, custom retention policies.
- **Usage Metering**: Tracks total scanned volumes, API requests, and storage utilization.

---

## Section 15: White-Label Customization

- **Custom Domain Routing**: Routes client requests based on Host header mapping.
- **Branding Assets**: Loads organization logos, customized CSS themes, and custom email banner templates.

---

## Section 16: API Connectors (SIEM/SOAR)

- **Connectors**:
  - **Splunk & Microsoft Sentinel**: Exposes endpoints to poll logs.
  - **Slack & Teams**: Webhook connectors push instant containment notifications to target channels.
  - **Jira & ServiceNow**: Triggers ticketing workflows when S1/S2 incidents are created.

---

## Section 17: Government Complaint Integration

- **National Cybercrime Portals**: Generates standardized complaint payload files to assist with reporting incidents to cybercrime cells.
- **Privacy Controls**: Redacts user PII from complaint submissions while preserving evidence payloads.

---

## Section 18: Governance & Audit Logs

- Tracks policy changes, API key provisioning, and role assignment actions.
- Audit collections are append-only.

---

## Section 19: Database Scaling & Partitioning

- **MongoDB Partitioning**: Matches `organization_id` as the partition key.
- **Eviction Strategy**: Employs TTL indexes to evict incident data older than the organization's retention policy.

---

## Section 20: Architectural Decision Records (ADRs)

### ADR-08: Logical Tenant Isolation using Query Filters
* **Decision**: Implement tenant isolation at the query filter level, using a shared database with tenant partitioning.
* **Trade-off**: A database-per-tenant architecture provides cleaner physical isolation, but dramatically increases server costs and orchestration overhead. Enforcing strict, automated query filters with the tenant's ID ensures data isolation while keeping system maintenance manageable.
