from typing import List
from app.models.email import RiskAnalysis, EmailRecommendation

class RecommendationService:
    @staticmethod
    def generate_recommendations(analysis: RiskAnalysis) -> EmailRecommendation:
        """Generate remediation recommendations, security tips, and threat explanations (Module 12)."""
        verdict = analysis.verdict
        score = int(analysis.risk_score * 100)
        indicators = analysis.indicators
        auth = analysis.auth_status

        suggestions = []
        next_steps = []
        security_tips = []
        explanation_parts = []

        # 1. Base Verdict & Actions
        if verdict == "CRITICAL":
            action_priority = "HIGH"
            action_type = "delete"
            explanation_parts.append(
                f"This email has a CRITICAL threat score of {score}/100. "
                "Multiple dangerous phishing indicators were detected, suggesting a deliberate cyberattack."
            )
            suggestions.append("DO NOT click any links, download attachments, or reply to this message.")
            next_steps.extend([
                "Report this email to your organization's IT Security/SOC team immediately.",
                "Delete the email from your inbox and purge it from your Trash folder."
            ])
        elif verdict == "HIGH":
            action_priority = "HIGH"
            action_type = "quarantine"
            explanation_parts.append(
                f"This email has a HIGH risk score of {score}/100. "
                "It contains indicators highly correlated with brand spoofing or credential theft."
            )
            suggestions.append("Treat this message with extreme caution. Avoid clicking links.")
            next_steps.extend([
                "Forward this incident to IT Security for analysis.",
                "Move the email to your Junk/Spam folder to train your mail client filters."
            ])
        elif verdict == "MEDIUM":
            action_priority = "MEDIUM"
            action_type = "review"
            explanation_parts.append(
                f"This email has a MEDIUM risk score of {score}/100. "
                "It is marked as suspicious due to content phrasing or missing authentication signatures."
            )
            suggestions.append("Verify the sender's identity through an alternate contact channel.")
            next_steps.append("Double check URLs before interacting with any website.")
        else:
            action_priority = "LOW"
            action_type = "allow"
            explanation_parts.append(
                f"This email has a LOW risk score of {score}/100. "
                "No critical threats or phishing patterns were detected."
            )
            suggestions.append("This email appears to be legitimate.")
            next_steps.append("Normal interaction is safe, but always remain vigilant.")

        # 2. Specific Indicator-based suggestions
        has_typosquatting = False
        has_spf_fail = False
        has_dmarc_fail = False
        has_credentials_request = False
        has_dangerous_attach = False

        for ind in indicators:
            ind_lower = ind.indicator.lower()
            if "typosquatting" in ind_lower or "spoofing" in ind_lower:
                has_typosquatting = True
            if "spf" in ind_lower:
                has_spf_fail = True
            if "dmarc" in ind_lower:
                has_dmarc_fail = True
            if "credential" in ind_lower:
                has_credentials_request = True
            if "attachment" in ind_lower:
                has_dangerous_attach = True

        # Append customized warnings
        if has_typosquatting:
            explanation_parts.append("The sender's domain is visually similar to a trusted brand, a common typosquatting technique.")
            suggestions.append("Verify if the domain name in the From address is spelled correctly.")
            security_tips.append("Attackers register domains like 'paypa1.com' or 'micros0ft.com' to deceive you.")

        if has_spf_fail or has_dmarc_fail:
            explanation_parts.append("The email failed sender authentication checks (SPF/DMARC), meaning it was sent by a third-party spoofing the sender's address.")
            suggestions.append("Treat the sender display name as untrusted.")
            security_tips.append("Sender authentication (SPF/DKIM/DMARC) helps verify that an email originated from the genuine domain owner.")

        if has_credentials_request:
            explanation_parts.append("The message asks for credentials, passcodes, or credit card updates.")
            suggestions.append("Never enter login credentials on websites reached via email links.")
            next_steps.append("If you already entered passwords, change them immediately and alert IT support.")
            security_tips.append("Legitimate organizations like banks or Google will never request passwords via email.")

        if has_dangerous_attach:
            explanation_parts.append("The email includes attachments with hazardous extensions (e.g. .exe, .js, .zip, .docm) which can run malware or ransomware.")
            suggestions.append("DO NOT open, extract, or run the attached files.")
            security_tips.append("Macro-enabled office documents (.docm, .xlsm) can download malware directly onto your system when opened.")

        # Default Security Awareness Tips
        security_tips.extend([
            "Look for signs of artificial urgency, such as threats of account suspension within 24 hours.",
            "Hover over links to preview the actual destination URL before clicking them."
        ])

        # Dedup lists
        suggestions = list(dict.fromkeys(suggestions))
        next_steps = list(dict.fromkeys(next_steps))
        security_tips = list(dict.fromkeys(security_tips))

        return EmailRecommendation(
            action_priority=action_priority,
            action_type=action_type,
            suggestions=suggestions[:4],
            next_steps=next_steps[:3],
            explanation=" ".join(explanation_parts),
            security_tips=security_tips[:4]
        )
