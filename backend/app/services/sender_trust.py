from typing import Dict, Any, Tuple, Optional
from app.repositories.sender_trust_repo import SenderTrustRepository

class SenderTrustService:
    @staticmethod
    async def evaluate_sender_trust(
        sender_email: str, 
        current_risk_score: float, 
        is_phishing: bool,
        repo: SenderTrustRepository
    ) -> Tuple[Dict[str, Any], bool, Optional[str]]:
        """Update sender historical aggregates and detect behavioral anomalies (Enhancement 2)."""
        email_clean = sender_email.lower().strip()
        
        # 1. Fetch previous trust record before updating
        existing = await repo.get_by_email(email_clean)
        
        # Default flags
        anomaly_detected = False
        anomaly_details = None
        
        if existing:
            total_scanned = existing.get("total_emails_scanned", 0)
            avg_risk = existing.get("average_risk_score", 0.0)
            
            # Anomaly checks: Only run if we have historical baseline (e.g. at least 3 prior emails)
            if total_scanned >= 3:
                # Check for sudden risk spike: current score is significantly higher than historical average
                # risk score ranges from 0.0 to 1.0
                if current_risk_score - avg_risk >= 0.35:
                    anomaly_detected = True
                    anomaly_details = (
                        f"Sender risk score spike! Historical average is {int(avg_risk * 100)}/100, "
                        f"but current email scored {int(current_risk_score * 100)}/100."
                    )
        
        # 2. Update stats in database
        updated_record = await repo.update_trust(email_clean, current_risk_score, is_phishing)
        
        return updated_record, anomaly_detected, anomaly_details
