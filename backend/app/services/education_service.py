from typing import Dict, Any, List

class CyberSafetyEducationService:
    # Educational definitions database
    THREAT_DEFINITIONS = {
        "spf_alignment_failure": {
            "title": "SPF Authentication Failure",
            "explanation": "Sender Policy Framework (SPF) verifies if the sending email server is authorized by the domain owner. A failure indicates the email may be spoofed by an unauthorized sender.",
            "safety_tip": "Do not trust the sender name. Check the envelope-from address and verify authenticity through secondary communication channels."
        },
        "dkim_signature_missing": {
            "title": "DKIM Signature Missing",
            "explanation": "DomainKeys Identified Mail (DKIM) adds a cryptographic signature to emails. A missing or invalid signature means there is no guarantee the message wasn't altered in transit.",
            "safety_tip": "Treat messages claiming to be from official services without DKIM signatures as suspicious."
        },
        "typosquatting_domain": {
            "title": "Domain Typosquatting",
            "explanation": "Attackers register domain names visually similar to well-known brands (e.g., 'paypa1.com' instead of 'paypal.com') to trick users into trusting a spoofed website.",
            "safety_tip": "Double-check individual characters in email address domains. Look closely for lookalike letters (like '1' for 'l', or 'rn' for 'm')."
        },
        "homograph_attack": {
            "title": "Unicode Homograph Spoofing",
            "explanation": "Attackers mix characters from different alphabets (like Cyrillic and Latin) that look identical but have different Unicode values, spoofing legitimate domain names.",
            "safety_tip": "Inspect raw links. Modern security monitors display Punycode prefixes (e.g. 'xn--...') to identify internationalized homograph spoofing."
        },
        "url_shortener": {
            "title": "URL Shortener Cloaking",
            "explanation": "Services like bit.ly or tinyurl hide the ultimate destination link. Intruders use them to bypass basic inbound filters and hide malicious payloads.",
            "safety_tip": "Avoid clicking shortened URLs in unsolicited emails. Use checkers that resolve links to their original locations beforehand."
        },
        "credential_request": {
            "title": "Social Engineering Credential Harvesting",
            "explanation": "Messages containing words like 'unlock account', 'verify details', or urgent payment directives are structured to trigger emotional panic, driving you to submit login credentials.",
            "safety_tip": "Official banks and institutions will never ask you to submit sensitive credentials or passwords over email links."
        }
    }

    @staticmethod
    def get_educational_materials(indicators: List[str]) -> List[Dict[str, Any]]:
        """Identify matching safety cards based on triggered indicator strings (Enhancement 8)."""
        materials = []
        ind_lower = [i.lower() for i in indicators]
        
        if any("spf" in i for i in ind_lower):
            materials.append(CyberSafetyEducationService.THREAT_DEFINITIONS["spf_alignment_failure"])
        if any("dkim" in i for i in ind_lower):
            materials.append(CyberSafetyEducationService.THREAT_DEFINITIONS["dkim_signature_missing"])
        if any("typosquatting" in i for i in ind_lower):
            materials.append(CyberSafetyEducationService.THREAT_DEFINITIONS["typosquatting_domain"])
        if any("homograph" in i or "punycode" in i for i in ind_lower):
            materials.append(CyberSafetyEducationService.THREAT_DEFINITIONS["homograph_attack"])
        if any("shortener" in i or "redirect" in i for i in ind_lower):
            materials.append(CyberSafetyEducationService.THREAT_DEFINITIONS["url_shortener"])
        if any("credential" in i or "urgency" in i or "locked" in i for i in ind_lower):
            materials.append(CyberSafetyEducationService.THREAT_DEFINITIONS["credential_request"])
            
        # Fallback if no matching indicator is found
        if not materials:
            materials.append({
                "title": "General Email Hygiene",
                "explanation": "Standard phishing attacks look to steal login credentials, access tokens, or install malware via malicious links or attachments.",
                "safety_tip": "Always inspect the sender details, avoid clicking unverified links, and do not download double-extension attachments."
            })
            
        return materials
