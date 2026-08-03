# Enterprise SOC Dashboard & Threat Correlation Engine Specification

This specification documents the Security Operations Center (SOC) dashboard console layout, correlation engine logic, MITRE ATT&CK tactic mappings, and SOAR automated playbook templates for **GuardianMail AI**.

---

## 1. SOC Dashboard Console Layout

```
+-------------------------------------------------------------------------------+
| GUARDIANMAIL AI | ENTERPRISE SOC CONSOLE                   [Role: SOC Analyst]|
+-------------------------------------------------------------------------------+
| [LIVE THREAT FEED]           | [OPEN INCIDENTS QUEUE]   | [SEVERITY HEATMAP]  |
| - 17:35:10 - IP 192.168.1.5  | - INC-2026-A23F (High)   |  [ Critical ] x 04  |
|   flagged url phishing       | - INC-2026-F981 (Medium) |  [   High   ] x 12  |
| - 17:34:02 - CEO Impersonate | - INC-2026-C098 (Low)    |  [  Medium  ] x 45  |
+-------------------------------------------------------------------------------+
| [IOC CORRELATION EXPLORER]                                                    |
|  Query: "paypal-update.net" --> Associated IP: 185.190.140.10                 |
|                            --> Related Campaigns: CAM-PAYPAL-2026-Q3          |
|                            --> Affected Users: admin@enterprise.com           |
+-------------------------------------------------------------------------------+
| [QUICK SOAR PLAYBOOK TRIGGER]                                                 |
|  [X] Quarantine email  [X] Block domain  [ ] Block IP  [X] Notify user        |
|  [Execute Selected containment actions]                                       |
+-------------------------------------------------------------------------------+
```

---

## 2. Threat Correlation Engine Algorithm

The correlation engine Groups individual email indicators, attachments hashes, domains, and IP reputations into unified **Security Incidents** to prevent alert fatigue:

### Correlation Rules Logic
Let $E_i$ represent incoming email alert instances. We group alerts into a single incident entity $INC_k$ if they share any of the following variables:
1. **Domain Cluster**: $E_a.sender\_domain == E_b.sender\_domain$
2. **Payload Match**: $E_a.attachment\_hash == E_b.attachment\_hash \neq None$
3. **URL Campaign**: $E_a.extracted\_urls \cap E_b.extracted\_urls \neq \emptyset$

---

## 3. MITRE ATT&CK Techniques Mapping

GuardianMail AI automatically maps detected threat factors to MITRE ATT&CK framework coordinates:

- **T1566 (Phishing)**:
  - **T1566.001 (Spearphishing Attachment)**: Triggered when attachment analysis finds executable headers or dangerous compressed macros.
  - **T1566.002 (Spearphishing Link)**: Triggered when URL reputation feeds flag target redirect paths.
- **T1078 (Valid Accounts)**:
  - **T1110.001 (Brute Force/Credential Spraying)**: Mapped when authentication headers display anomalous routing or reply-to discrepancies.
- **T1204 (User Execution)**:
  - **T1204.001 (Malicious Link Click)**: Associated when email timeline tracking log records user-interaction.

---

## 4. SOC Threat Intelligence Fusion & Confidence Matrix

We fuse threat data from multiple reputation feeds, applying weights based on feed confidence:

| Threat Feed Provider | Intelligence Scope | Confidence Weight | Default Cache TTL |
| :--- | :--- | :--- | :--- |
| **VirusTotal** | Attachment hashes | **0.95** | 24 hours |
| **AbuseIPDB** | Sender IP addresses | **0.90** | 12 hours |
| **URLhaus** | Malware link databases | **0.92** | 6 hours |
| **OpenPhish** | Phishing URL endpoints | **0.88** | 3 hours |

---

## 5. SOAR Automated Containment Playbook

Configurable automated playbooks trigger on incident escalation:
```json
{
  "playbook_id": "PLAYBOOK-SEV1-AUTOCONTAIN",
  "triggers": {
    "severity": ["CRITICAL"],
    "verdict": ["PHISHING", "MALWARE"]
  },
  "actions": [
    {
      "step": 1,
      "action": "QUARANTINE_EMAIL",
      "scope": "RECIPIENT_INBOX"
    },
    {
      "step": 2,
      "action": "BLOCK_DOMAIN",
      "target": "SENDER_DOMAIN",
      "router": "FORTINET_NGFW_API"
    },
    {
      "step": 3,
      "action": "NOTIFY_USER",
      "template": "PHISHING_ALERT_WARNED"
    }
  ]
}
```
