# E13.9 — Continuous Threat Intelligence & Risk Correlation Report

## 1. Executive Summary
This document establishes the threat indicators normalization, confidence decay rules, and tenant scoping for the **GuardianMail AI** platform.

Every threat intelligence flow conforms strictly to the E13 baseline contract, requiring that matches trigger notifications but cannot directly invoke E6 containment actions.

---

## 2. Threat Indicator Normalization

Domain extraction converts raw strings and URLs to lowercase host names:

$$\text{Domain extraction}: \text{HTTP://BAD.COM/path} \rightarrow \text{bad.com}$$

---

## 3. Threat Posture & Confidence Decay

Indicator confidence decays dynamically by 5% per day to control staleness:

$$\text{Confidence}_T = \text{Base Score} \times (0.95)^{\text{days old}}$$

---

## 4. Automated Test Verification Results

### Targeted Threat Intelligence Tests:
```
tests/test_e13_9_threat_intel_correlation.py::test_threat_indicator_normalization[asyncio] PASSED
tests/test_e13_9_threat_intel_correlation.py::test_confidence_decay_and_expiration[asyncio] PASSED
tests/test_e13_9_threat_intel_correlation.py::test_tenant_scoped_threat_isolation[asyncio] PASSED
tests/test_e13_9_threat_intel_correlation.py::test_e6_boundary_enforcement[asyncio] PASSED

======================== 4 passed in 0.10s ========================
```

### Consolidated Regression Suite:
```
================ 287 passed, 11 warnings in 113.72s (0:01:53) =================
```

---

## 5. Verdict

**E13.9 ACCEPTED 🟢**
Threat indicator normalizations, confidence decay calculations, and safe E6 boundaries are fully validated.
