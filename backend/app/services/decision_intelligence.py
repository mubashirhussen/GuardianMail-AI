import logging
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from app.models.email import RiskAnalysis, ThreatIndicator
from app.services.intel_providers.implementations import (
    GoogleSafeBrowsingProvider, VirusTotalProvider, AbuseIPDBProvider, DNSWhoisProvider, IPGeoProvider
)

logger = logging.getLogger(__name__)

class DecisionIntelligenceService:
    """Centralized Decision Intelligence and Attack Correlation Engine."""

    @staticmethod
    async def evaluate_threat_intelligence(email_rec: Dict[str, Any], db: Optional[Any] = None) -> Dict[str, Any]:
        """Trigger threat providers, scan campaign patterns, and compile overall unified security verdicts."""
        start_time = time.time()
        
        # 1. Initialize providers
        safe_browsing = GoogleSafeBrowsingProvider()
        vt = VirusTotalProvider()
        abuse_ipdb = AbuseIPDBProvider()
        whois = DNSWhoisProvider()
        geo = IPGeoProvider()
        
        from_address = email_rec.get("from_address", "")
        from_domain = email_rec.get("sender_domain") or from_address.split("@")[-1] if "@" in from_address else ""
        urls = email_rec.get("urls", [])
        attachments = email_rec.get("attachments", [])
        
        # Determine client IP from headers or route patterns
        client_ip = "127.0.0.1"
        
        provider_logs = []
        malicious_indicators = 0
        total_checks = 0
        
        # A. Check Domain Age and registrar WHOIS details
        if from_domain:
             total_checks += 1
             w_res = await whois.lookup(from_domain)
             provider_logs.append({"provider": "DNSWhois", "result": w_res})
             if w_res.get("malicious"):
                  malicious_indicators += 1
                  
        # B. Check embedded URLs with Safe Browsing and VirusTotal
        for url_item in urls[:3]: # Limit to first 3 to avoid API exhaustions
             url_str = url_item.get("original_url") or url_item.get("url") or ""
             if url_str:
                  total_checks += 1
                  sb_res = await safe_browsing.lookup(url_str)
                  provider_logs.append({"provider": "GoogleSafeBrowsing", "result": sb_res})
                  if sb_res.get("malicious"):
                       malicious_indicators += 1
                       
                  # VirusTotal URL check
                  total_checks += 1
                  vt_res = await vt.lookup(url_str)
                  provider_logs.append({"provider": "VirusTotal", "result": vt_res})
                  if vt_res.get("malicious"):
                       malicious_indicators += 1

        # C. Scan AbuseIPDB for Sender IP reputation
        if client_ip and client_ip != "127.0.0.1":
             total_checks += 1
             ip_res = await abuse_ipdb.lookup(client_ip)
             provider_logs.append({"provider": "AbuseIPDB", "result": ip_res})
             if ip_res.get("malicious"):
                  malicious_indicators += 1
                  
             # Geolocation info
             geo_res = await geo.lookup(client_ip)
             provider_logs.append({"provider": "IPGeo", "result": geo_res})

        # 2. Attack Correlation & Campaign Scan Heuristics
        campaign_detected = False
        campaign_name = "None"
        campaign_ev = []
        if db and from_domain:
             # Look for similar domain records in emails collection in the past 24 hours
             day_ago = datetime.now(timezone.utc) - timedelta(days=1)
             cursor = db["emails"].find({
                 "sender_domain": from_domain,
                 "created_at": {"$gte": day_ago}
             })
             domain_count = await cursor.to_list(length=100)
             if len(domain_count) >= 5:
                  campaign_detected = True
                  campaign_name = f"Suspicious Activity Campaign from domain {from_domain}"
                  campaign_ev.append(f"Identified {len(domain_count)} email attempts from domain '{from_domain}' in the past 24 hours (BEC campaign alert).")

        # 3. Decision Score & Verdict Compiling
        # AI score from Phase 6
        ai_analysis = email_rec.get("analysis") or {}
        ai_score = ai_analysis.get("risk_score", 0.0)
        
        # Intel score
        intel_score = (malicious_indicators / total_checks) if total_checks > 0 else 0.0
        if campaign_detected:
             intel_score = max(intel_score, 0.80)
             
        # Combine
        combined_score = (ai_score * 0.50) + (intel_score * 0.50)
        
        # Verdict decision logic
        verdict = "SAFE"
        severity = "LOW"
        if combined_score >= 0.70:
             verdict = "PHISHING"
             severity = "HIGH"
             if campaign_detected:
                  verdict = "BEC"
                  severity = "CRITICAL"
        elif combined_score >= 0.40:
             verdict = "SUSPICIOUS"
             severity = "MEDIUM"
        elif combined_score >= 0.20:
             verdict = "SPAM"
             
        # Actionable recommendations builder
        suggestions = ["Monitor email interactions."]
        next_steps = []
        if verdict in ["PHISHING", "BEC", "SUSPICIOUS"]:
             suggestions.extend([
                 "Block Sender Display Name.",
                 "Report threat indicators to the organization Security Operations Center (SOC)."
             ])
             next_steps.extend([
                 "Block sender email address in mail filters.",
                 "Flag lookalike brand domains in DNS policy settings."
             ])
             if attachments:
                  suggestions.append("Quarantine dangerous email attachments.")
                  next_steps.append("Run antivirus endpoint sweeps on user systems.")
        else:
             suggestions.append("Email is safe to deliver.")
             
        duration = time.time() - start_time
        
        return {
            "verdict": verdict,
            "overall_risk_score": combined_score,
            "severity": severity,
            "duration_ms": int(duration * 1000),
            "campaign": {
                "detected": campaign_detected,
                "name": campaign_name,
                "evidence": campaign_ev
            },
            "provider_logs": provider_logs,
            "mitre_attack_mapping": [
                "T1566.002 - Phishing: Spearphishing Link" if urls else "T1566.001 - Phishing: Spearphishing Attachment"
            ] if verdict in ["PHISHING", "BEC"] else [],
            "recommendations": {
                "suggestions": suggestions,
                "next_steps": next_steps
            }
        }

from datetime import timedelta
