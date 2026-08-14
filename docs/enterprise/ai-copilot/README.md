# AI Security Copilot Architecture Reference (Workstream E5)

This reference outlines the design and operation of the AI Security Copilot built to assist security operations center (SOC) analysts in threat diagnostics, investigation summarization, and query execution.

---

## 1. System Architecture

```
                       Analyst Input
                             │
                             ▼
                    Copilot API Router
                             │
                             ▼
                    Copilot Orchestrator
                             │
             ┌───────────────┼───────────────┐
             ▼               ▼               ▼
       Intent Router    Context RAG    Privacy Redactor
             │               │               │
             └───────────────┼───────────────┘
                             ▼
                      Grounded Prompt
                             │
                             ▼
                        LLM Provider
                             │
                             ▼
                      Output Sanitizer
                             │
                             ▼
                        Analyst UI
```

---

## 2. LLM Provider Abstraction
The system utilizes a central service abstraction mapping queries to configured backends:
- **Google Gemini**: Standard low-latency analysis.
- **OpenAI**: Configurable for GPT models.
- **Anthropic**: Configurable Claude models.
- **Local/Self-hosted Stubs**: Default fallback for air-gapped/restricted networks.

---

## 3. Retrieval-Augmented Generation (RAG)
Context is assembled dynamically based on identified intent types:
1. **THREAT_EXPLANATION**: Joins email headers, extracted indicators, and policies.
2. **INCIDENT_SUMMARY**: Queries incident timelines and forensic evidence bundles.
3. **IOC_ANALYSIS**: Resolves indicator records using E4 Threat Intelligence data.
4. **SECURITY_POLICY_QUERY**: Queries compiled policy engine parameters.

---

## 4. Privacy & Redaction Controls
To comply with E3 Privacy policies, the Copilot enforces the following before data reaches external APIs:
- **Redaction Regex**: Sanitizes passwords, access tokens, API keys, and session credentials.
- **AI Policy Check**: Evaluates the `ai_analysis` policy. If the verdict is `DENY` or `BLOCK`, the Copilot stops execution and returns a policy rejection notice.

---

## 5. Prompt Injection Defense
- **Strict Structural Boundaries**: System instructions are strictly isolated from untrusted input parameters.
- **Keyword Filters**: Rejects instructions bypass requests (e.g., "Ignore previous instructions") with a `CRITICAL_RISK` warning verdict.
- **No Autonomous Execution**: Copilot has read-only database query execution permissions. It can recommend actions, but cannot alter system settings without administrator manual sign-off.
