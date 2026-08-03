from typing import Dict, Any, List

class CredentialRecoveryService:
    @staticmethod
    def get_recovery_checklist(verdict: str, indicators: List[str]) -> List[Dict[str, Any]]:
        """Generate interactive recovery items based on threat elements identified (Enhancement 5)."""
        checklist = []
        
        # 1. Base recovery steps (Enforced when threat is Medium or higher)
        if verdict in ["CRITICAL", "HIGH", "MEDIUM"]:
            checklist.append({
                "item_id": "reset_password",
                "title": "Reset Credentials",
                "category": "Credentials",
                "priority": "HIGH",
                "description": "Reset your email password immediately. Enforce a strong passphrase of 12+ characters.",
                "actions": ["Create unique password", "Update password managers"]
            })
            checklist.append({
                "item_id": "audit_active_sessions",
                "title": "Audit Active Sessions",
                "category": "Session",
                "priority": "HIGH",
                "description": "Revoke active login sessions on all other devices to force sign-out of potential intruders.",
                "actions": ["Visit Device Activity panel", "Terminate unfamiliar active sessions"]
            })
            checklist.append({
                "item_id": "audit_oauth_grants",
                "title": "Review Third-Party OAuth Access",
                "category": "OAuth",
                "priority": "MEDIUM",
                "description": "Inspect permissions granted to external APIs or OAuth app scopes.",
                "actions": ["Visit Google Security Connected Apps Settings", "Revoke unverified API app keys"]
            })
            
        # 2. Add specific checklist elements based on threat indicators
        ind_lower = [i.lower() for i in indicators]
        
        has_phish = any("credential" in i or "login" in i or "password" in i or "auth" in i for i in ind_lower)
        if has_phish or verdict == "CRITICAL":
            checklist.append({
                "item_id": "enable_mfa",
                "title": "Enforce Multi-Factor Authentication (MFA)",
                "category": "MFA",
                "priority": "HIGH",
                "description": "Secure account with hardware keys, authenticator apps (TOTP), or phone keys.",
                "actions": ["Setup Google Authenticator / YubiKey", "Download backup codes"]
            })
            
        if any("billing" in i or "bank" in i or "invoice" in i or "wire" in i for i in ind_lower):
            checklist.append({
                "item_id": "alert_finance",
                "title": "Contact Financial Providers",
                "category": "Finance",
                "priority": "HIGH",
                "description": "If bank or billing info was submitted, contact your bank to freeze transactions.",
                "actions": ["Call bank support", "Check statements for charge anomalies"]
            })
            
        return checklist
