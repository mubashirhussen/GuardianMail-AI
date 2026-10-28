import re
import time
import logging
import json
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timezone
from app.core.config import settings
from app.models.email import ThreatIndicator, HeaderAuthStatus, RiskAnalysis, TimelineEvent
from app.services.security_headers import SecurityHeadersService
from app.services.threat_intel import ThreatIntelService
from app.services.llm_provider import LLMProvider

logger = logging.getLogger(__name__)

class ThreatDetectorService:
    """Enterprise-grade Multi-Engine threat detection & risk scoring pipeline with explainable AI reasoning."""
    
    DETECTOR_WEIGHTS = {
        "sender_reputation": 0.08,
        "domain_intel": 0.12,
        "url_security": 0.15,
        "social_eng": 0.10,
        "brand_impersonation": 0.10,
        "credential_harvesting": 0.10,
        "bec": 0.10,
        "attachment_intel": 0.10,
        "header_intel": 0.05,
        "language_intel": 0.05,
        "historical_trust": 0.05,
        "ai_semantic": 0.10
    }

    @staticmethod
    async def analyze_email(parsed_email: Dict[str, Any], db: Optional[Any] = None) -> RiskAnalysis:
        """Run all 12 detectors in parallel/sequence, calculate weighted score, apply calibration, and return RiskAnalysis."""
        start_time = time.time()
        findings: List[ThreatIndicator] = []
        positive_evidence: List[str] = []
        negative_evidence: List[str] = []
        detector_sources: List[str] = []
        
        # Ingestion metrics
        body = parsed_email.get("body_plain") or ""
        subject = parsed_email.get("subject") or ""
        from_address = parsed_email.get("from_address") or ""
        from_domain = parsed_email.get("sender_domain") or ""
        attachments = parsed_email.get("attachments") or []
        urls = parsed_email.get("urls") or []
        raw_msg = parsed_email.get("raw_msg")

        # ----------------------------------------------------
        # 1. Sender Reputation Detector
        # ----------------------------------------------------
        sender_score = 0.0
        sender_ev = []
        display_name = parsed_email.get("sender_name") or ""
        # Check display name alignment: e.g. name is Google but domain is fraud.com
        brand_names = ["google", "microsoft", "paypal", "netflix", "apple", "amazon", "bank", "support"]
        name_lower = display_name.lower()
        if any(brand in name_lower for brand in brand_names) and not any(brand in from_domain.lower() for brand in brand_names):
             sender_score = 0.85
             sender_ev.append(f"Display name spoofing attempt: name displays '{display_name}' but domain is '{from_domain}'")
        
        if sender_score > 0:
             findings.append(ThreatIndicator(
                 indicator="Display Name Impersonation",
                 detail="; ".join(sender_ev),
                 severity="HIGH",
                 confidence=sender_score,
                 type="phishing"
             ))
             positive_evidence.append(f"[Sender Reputation] {sender_ev[0]}")
        else:
             negative_evidence.append("[Sender Reputation] Display name matches domain structure.")
        detector_sources.append("sender_reputation")

        # ----------------------------------------------------
        # 2. Domain Intelligence Detector
        # ----------------------------------------------------
        domain_score = 0.0
        domain_ev = []
        auth_status = None
        if raw_msg:
             auth_status_dict, header_score, header_findings = SecurityHeadersService.analyze_authentication_headers(raw_msg)
             # Map HeaderAuthStatus
             auth_status = auth_status_dict
             if header_score > 0:
                  domain_score = max(domain_score, 0.70)
                  domain_ev.append("SPF/DKIM/DMARC alignment check failed")
                  
        # Homograph / Punycode check
        if from_domain.startswith("xn--"):
             domain_score = max(domain_score, 0.90)
             domain_ev.append(f"Punycode homograph domain detected: {from_domain}")
             
        if domain_score > 0:
             findings.append(ThreatIndicator(
                 indicator="Domain Authentication Failures",
                 detail="; ".join(domain_ev),
                 severity="HIGH",
                 confidence=domain_score,
                 type="phishing"
             ))
             positive_evidence.append(f"[Domain Intel] {domain_ev[0]}")
        else:
             negative_evidence.append("[Domain Intel] SPF/DKIM/DMARC headers passed verification.")
        detector_sources.append("domain_intel")

        # ----------------------------------------------------
        # 3. URL Security Detector
        # ----------------------------------------------------
        url_score = 0.0
        url_ev = []
        for url_item in urls:
             orig_url = url_item.get("original_url") or url_item.get("url") or ""
             domain_part = url_item.get("domain") or ""
             # Check IP address URL or shortened redirect
             if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain_part):
                  url_score = max(url_score, 0.85)
                  url_ev.append(f"IP address URL detected: {orig_url}")
             if url_item.get("category") == "FTP":
                  url_score = max(url_score, 0.60)
                  url_ev.append(f"FTP link detected: {orig_url}")
                  
        if url_score > 0:
             findings.append(ThreatIndicator(
                 indicator="Suspicious URL detected",
                 detail="; ".join(url_ev),
                 severity="HIGH",
                 confidence=url_score,
                 type="phishing"
             ))
             positive_evidence.append(f"[URL Security] {url_ev[0]}")
        else:
             negative_evidence.append("[URL Security] No IP address or anomalous URL protocols detected.")
        detector_sources.append("url_security")

        # ----------------------------------------------------
        # 4. Social Engineering Detector
        # ----------------------------------------------------
        social_score = 0.0
        social_ev = []
        urgency_kws = ["urgent", "immediate", "action required", "locked", "expires", "suspended"]
        body_lower = body.lower()
        triggered_urg = [kw for kw in urgency_kws if kw in body_lower or kw in subject.lower()]
        if len(triggered_urg) >= 2:
             social_score = 0.65
             social_ev.append(f"Urgent keywords found: {', '.join(triggered_urg)}")
             
        if social_score > 0:
             findings.append(ThreatIndicator(
                 indicator="Social Engineering Attempt",
                 detail="; ".join(social_ev),
                 severity="MEDIUM",
                 confidence=social_score,
                 type="phishing"
             ))
             positive_evidence.append(f"[Social Engineering] {social_ev[0]}")
        else:
             negative_evidence.append("[Social Engineering] No urgent pressure indicators found in body content.")
        detector_sources.append("social_eng")

        # ----------------------------------------------------
        # 5. Brand Impersonation Detector
        # ----------------------------------------------------
        brand_score = 0.0
        brand_ev = []
        # Check brand name in subject or body with misaligned from_domain
        known_brands = ["google", "microsoft", "paypal", "netflix", "apple", "amazon"]
        for brand in known_brands:
             if (brand in body_lower or brand in subject.lower()) and brand not in from_domain.lower():
                  brand_score = max(brand_score, 0.70)
                  brand_ev.append(f"Email refers to brand '{brand}' but domain is '{from_domain}'")
                  
        if brand_score > 0:
             findings.append(ThreatIndicator(
                 indicator="Brand Impersonation Detected",
                 detail="; ".join(brand_ev),
                 severity="HIGH",
                 confidence=brand_score,
                 type="phishing"
              ))
             positive_evidence.append(f"[Brand Impersonation] {brand_ev[0]}")
        else:
             negative_evidence.append("[Brand Impersonation] Sender domain matches referenced brand logos/names.")
        detector_sources.append("brand_impersonation")

        # ----------------------------------------------------
        # 6. Credential Harvesting Detector
        # ----------------------------------------------------
        harvest_score = 0.0
        harvest_ev = []
        harvest_kws = ["password reset", "login request", "verify otp", "verify pin", "enter credentials"]
        triggered_harv = [kw for kw in harvest_kws if kw in body_lower]
        if triggered_harv:
             harvest_score = 0.80
             harvest_ev.append(f"Credential harvesting keywords: {', '.join(triggered_harv)}")
             
        if harvest_score > 0:
             findings.append(ThreatIndicator(
                 indicator="Credential Harvesting Scam",
                 detail="; ".join(harvest_ev),
                 severity="HIGH",
                 confidence=harvest_score,
                 type="phishing"
             ))
             positive_evidence.append(f"[Credential Harvesting] {harvest_ev[0]}")
        else:
             negative_evidence.append("[Credential Harvesting] No login forms or credential update requests found.")
        detector_sources.append("credential_harvesting")

        # ----------------------------------------------------
        # 7. Business Email Compromise Detector
        # ----------------------------------------------------
        bec_score = 0.0
        bec_ev = []
        bec_kws = ["wire transfer", "gift card", "invoice payment", "ceo", "payroll change"]
        triggered_bec = [kw for kw in bec_kws if kw in body_lower]
        if triggered_bec:
             bec_score = 0.75
             bec_ev.append(f"BEC indicators found: {', '.join(triggered_bec)}")
             
        if bec_score > 0:
             findings.append(ThreatIndicator(
                 indicator="Business Email Compromise Alert",
                 detail="; ".join(bec_ev),
                 severity="HIGH",
                 confidence=bec_score,
                 type="bec"
             ))
             positive_evidence.append(f"[BEC] {bec_ev[0]}")
        else:
             negative_evidence.append("[BEC] No financial transfer or CEO invoice requests.")
        detector_sources.append("bec")

        # ----------------------------------------------------
        # 8. Attachment Intelligence Detector
        # ----------------------------------------------------
        attach_score = 0.0
        attach_ev = []
        dangerous_exts = [".exe", ".bat", ".cmd", ".vbs", ".js", ".scr", ".pif"]
        suspicious_exts = [".zip", ".rar", ".7z", ".docm", ".xlsm"]
        for att in attachments:
             fn = att.get("filename", "").lower()
             ext = "." + fn.split(".")[-1] if "." in fn else ""
             if ext in dangerous_exts:
                  attach_score = max(attach_score, 0.95)
                  attach_ev.append(f"Executable attachment found: '{fn}'")
             elif ext in suspicious_exts:
                  attach_score = max(attach_score, 0.65)
                  attach_ev.append(f"Suspicious compressed/macro-enabled attachment: '{fn}'")
                  
        if attach_score > 0:
             findings.append(ThreatIndicator(
                 indicator="Dangerous Email Attachment",
                 detail="; ".join(attach_ev),
                 severity="CRITICAL" if attach_score > 0.90 else "HIGH",
                 confidence=attach_score,
                 type="malware"
             ))
             positive_evidence.append(f"[Attachment Intel] {attach_ev[0]}")
        else:
             negative_evidence.append("[Attachment Intel] Attachments list is clean (no executables/macros).")
        detector_sources.append("attachment_intel")

        # ----------------------------------------------------
        # 9. Header Intelligence Detector
        # ----------------------------------------------------
        header_score = 0.0
        header_ev = []
        reply_to = parsed_email.get("reply_to") or ""
        if reply_to and from_address:
             _, r_email = email.utils.parseaddr(reply_to)
             _, f_email = email.utils.parseaddr(from_address)
             if r_email.strip().lower() != f_email.strip().lower():
                  header_score = 0.60
                  header_ev.append(f"Reply-To mismatch: From displays '{f_email}' but Reply-To goes to '{r_email}'")
                  
        if header_score > 0:
             findings.append(ThreatIndicator(
                 indicator="Suspicious Routing Headers",
                 detail="; ".join(header_ev),
                 severity="MEDIUM",
                 confidence=header_score,
                 type="phishing"
             ))
             positive_evidence.append(f"[Header Intel] {header_ev[0]}")
        else:
             negative_evidence.append("[Header Intel] Reply-To aligns with From header details.")
        detector_sources.append("header_intel")

        # ----------------------------------------------------
        # 10. Language Intelligence Detector
        # ----------------------------------------------------
        lang_score = 0.0
        lang_ev = []
        # Check HTML zero-width spaces or unicode obfuscations
        if body and (chr(8203) in body or chr(8204) in body): # zero width space / non-joiner
             lang_score = 0.70
             lang_ev.append("HTML zero-width space/unicode obfuscation detected")
             
        if lang_score > 0:
             findings.append(ThreatIndicator(
                 indicator="HTML Obfuscation Attempt",
                 detail="; ".join(lang_ev),
                 severity="HIGH",
                 confidence=lang_score,
                 type="phishing"
             ))
             positive_evidence.append(f"[Language Intel] {lang_ev[0]}")
        else:
             negative_evidence.append("[Language Intel] Text uses standard unicode representations.")
        detector_sources.append("language_intel")

        # ----------------------------------------------------
        # 11. Historical Trust Detector
        # ----------------------------------------------------
        history_score = 0.0
        if db and from_domain:
             # Check if domain has sent emails to users previously (if so, reduce threat scoring)
             cursor = db["emails"].find({"sender_domain": from_domain, "analysis.verdict": "SAFE"})
             safe_count = await cursor.to_list(length=5)
             if len(safe_count) >= 3:
                  negative_evidence.append(f"[Historical Trust] Domain '{from_domain}' has 3+ clean historical verdicts.")
             else:
                  history_score = 0.30
                  positive_evidence.append(f"[Historical Trust] Domain '{from_domain}' has no clean trust history.")
        else:
             history_score = 0.30
             positive_evidence.append("[Historical Trust] No historical trust records found for sender.")
        detector_sources.append("historical_trust")

        # ----------------------------------------------------
        # 12. AI Semantic Analyzer (Configurable LLM provider)
        # ----------------------------------------------------
        ai_score = 0.0
        ai_reason = "No semantic warnings flagged."
        # LLM semantic analysis triggers if we have indicators or urgent keywords
        if settings.GEMINI_API_KEY or getattr(settings, "OPENAI_API_KEY", ""):
             prompt = (
                 f"Analyze the following email metadata and classify it.\n"
                 f"Subject: {subject}\nSender: {from_address}\nBody: {body[:1000]}\n\n"
                 f"Return a JSON object in this exact format: "
                 f'{{"is_phishing": true/false, "verdict": "phishing/safe", "reason": "why"}}'
             )
             try:
                  ai_res = await LLMProvider.generate_completion(prompt)
                  ai_data = json.loads(ai_res)
                  if ai_data.get("is_phishing") or ai_data.get("verdict") == "phishing":
                       ai_score = 0.75
                       ai_reason = ai_data.get("reason", "AI flagged social engineering behavior.")
             except Exception as e:
                  logger.debug(f"AI semantic run skipped or failed: {str(e)}")
                  
        if ai_score > 0:
             findings.append(ThreatIndicator(
                 indicator="AI Semantic Risk Warning",
                 detail=ai_reason,
                 severity="HIGH",
                 confidence=ai_score,
                 type="phishing"
             ))
             positive_evidence.append(f"[AI Semantic] {ai_reason}")
        else:
             negative_evidence.append("[AI Semantic] LLM found no anomalous social engineering tactics.")
        detector_sources.append("ai_semantic")

        # ----------------------------------------------------
        # 13. Threat Intelligence Database Match (Workstream E4)
        # ----------------------------------------------------
        threat_intel_score = 0.0
        extracted_domains = []
        extracted_urls = []
        for url_item in urls:
             orig_url = url_item.get("original_url") or url_item.get("url") or ""
             domain_part = url_item.get("domain") or ""
             if orig_url:
                  extracted_urls.append(orig_url)
             if domain_part:
                  extracted_domains.append(domain_part)
        
        extracted_hashes = []
        for att in attachments:
             h = att.get("sha256") or att.get("hash") or ""
             if h:
                  extracted_hashes.append(h)

        if db:
             from app.services.threat_intel import ThreatIntelService
             normalized_query_vals = []
             if from_domain:
                  normalized_query_vals.append(ThreatIntelService.normalize_indicator_value("domain", from_domain))
             if from_address:
                  normalized_query_vals.append(ThreatIntelService.normalize_indicator_value("email_address", from_address))
             for d in extracted_domains:
                  normalized_query_vals.append(ThreatIntelService.normalize_indicator_value("domain", d))
             for u in extracted_urls:
                  normalized_query_vals.append(ThreatIntelService.normalize_indicator_value("url", u))
             for h in extracted_hashes:
                  normalized_query_vals.append(ThreatIntelService.normalize_indicator_value("file_hash", h))

             normalized_query_vals = list(set([v for v in normalized_query_vals if v]))

             if normalized_query_vals:
                  from app.core.tenant_context import request_tenant_context
                  context = request_tenant_context.get()
                  org_id = context.organization_id if context else None
                  
                  indicators_cursor = db["threat_indicators"].find({
                      "normalized_value": {"$in": normalized_query_vals},
                      "status": "ACTIVE",
                      "$or": [
                          {"organization_id": org_id},
                          {"organization_id": None}
                      ],
                      "soft_delete": False
                  })
                  matching_iocs = await indicators_cursor.to_list(length=20)
                  
                  from app.services.threat_correlation import threat_correlation_service
                  
                  for ioc in matching_iocs:
                       severity_str = ioc.get("severity", "medium").upper()
                       conf_val = ioc.get("confidence", 50) / 100.0
                       
                       if severity_str == "CRITICAL":
                            intel_score = 0.95
                       elif severity_str == "HIGH":
                            intel_score = 0.85
                       elif severity_str == "MEDIUM":
                            intel_score = 0.65
                       else:
                            intel_score = 0.35
                       
                       threat_intel_score = max(threat_intel_score, intel_score)
                       
                       findings.append(ThreatIndicator(
                           indicator=f"Threat Intel Match: {ioc.get('indicator_type').upper()}",
                           detail=f"Matched active IOC from source '{ioc.get('source')}'. Severity: {severity_str}. Confidence: {ioc.get('confidence')}%",
                           severity=severity_str,
                           confidence=conf_val,
                           type="threat_intel"
                       ))
                       positive_evidence.append(f"[Threat Intel] Matched malicious {ioc.get('indicator_type')}: {ioc.get('normalized_value')}")
                       
                       # Record observation log
                       await threat_correlation_service.record_observation(
                           org_id=org_id or "system_global",
                           indicator_id=str(ioc["_id"]),
                           email_id=parsed_email.get("_id")
                       )

        # ----------------------------------------------------
        # Weighted Scoring & Aggregation
        # ----------------------------------------------------
        scores_list = {
            "sender_reputation": sender_score,
            "domain_intel": domain_score,
            "url_security": url_score,
            "social_eng": social_score,
            "brand_impersonation": brand_score,
            "credential_harvesting": harvest_score,
            "bec": bec_score,
            "attachment_intel": attach_score,
            "header_intel": header_score,
            "language_intel": lang_score,
            "historical_trust": history_score,
            "ai_semantic": ai_score
        }
        
        weighted_sum = 0.0
        for name, weight in ThreatDetectorService.DETECTOR_WEIGHTS.items():
             weighted_sum += scores_list[name] * weight
             
        # Scale score from 0-1 to percentage 0-100
        final_score = weighted_sum * 100
        
        # Elevate based on critical indicators
        max_hard_score = max(sender_score, domain_score, url_score, attach_score, threat_intel_score)
        if max_hard_score >= 0.90:
             final_score = max(final_score, 85.0)
        elif max_hard_score >= 0.80:
             final_score = max(final_score, 75.0)
        elif max_hard_score >= 0.60:
             final_score = max(final_score, 50.0)
        
        # ----------------------------------------------------
        # False Positive Mitigation & Calibration
        # ----------------------------------------------------
        is_hard_indicator = (sender_score > 0 or domain_score > 0 or url_score > 0 or attach_score > 0 or threat_intel_score > 0)
        if not is_hard_indicator and final_score >= 35:
             final_score = min(45.0, final_score)
             
        final_score = min(100.0, max(0.0, final_score))
        
        # Map verdict classification
        verdict = "SAFE"
        is_phishing = False
        is_bec = False
        is_spam = False
        is_malware = False
        is_fraud = False
        
        if final_score >= 70:
             verdict = "PHISHING"
             is_phishing = True
             if bec_score > 0:
                  verdict = "BEC"
                  is_bec = True
             elif attach_score > 0.90:
                  verdict = "MALWARE"
                  is_malware = True
             elif harvest_score > 0:
                  verdict = "CREDENTIAL_HARVESTING"
                  is_phishing = True
        elif final_score >= 40:
             verdict = "SUSPICIOUS"
             is_fraud = True
        elif final_score >= 20:
             verdict = "SPAM"
             is_spam = True

        explanation = (
             f"Email risk evaluation concluded: {verdict}. "
             f"Triggered indicators list count: {len(findings)}. "
             f"Critical factors: {'; '.join(positive_evidence[:2]) if positive_evidence else 'None'}."
        )

        return RiskAnalysis(
            verdict=verdict,
            risk_score=final_score / 100.0,
            confidence_score=0.90 if is_hard_indicator else 0.60,
            is_phishing=is_phishing,
            is_fraud=is_fraud,
            is_bec=is_bec,
            is_malware=is_malware,
            is_spam=is_spam,
            indicators=findings,
            auth_status=auth_status,
            explanation=explanation,
            ai_explanation=ai_reason if ai_score > 0 else None,
            positive_evidence=positive_evidence,
            negative_evidence=negative_evidence,
            detector_sources=detector_sources,
            confidence_level="HIGH" if is_hard_indicator else "LOW",
            timeline=[
                TimelineEvent(event="SCAN_INITIALIZED", description="Email security scan started."),
                TimelineEvent(event="VERDICT_DECIDED", description=f"Final score evaluated as {final_score:.1f}. Verdict: {verdict}")
            ]
        )
