from typing import Dict, Any, Optional
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

class SenderTrustRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "sender_trust")

    async def get_by_email(self, sender_email: str) -> Optional[Dict[str, Any]]:
        """Fetch sender trust record by email."""
        record = await self.collection.find_one({"sender_email": sender_email.lower().strip()})
        if record:
            record["_id"] = str(record["_id"])
        return record

    async def update_trust(self, sender_email: str, risk_score: float, is_phishing: bool) -> Dict[str, Any]:
        """Update historical aggregates and compute new averages for a sender."""
        email_clean = sender_email.lower().strip()
        existing = await self.get_by_email(email_clean)
        
        now = datetime.now(timezone.utc)
        
        if existing:
            total = existing.get("total_emails_scanned", 0) + 1
            safe = existing.get("safe_emails_count", 0) + (0 if is_phishing else 1)
            phish = existing.get("phishing_emails_count", 0) + (1 if is_phishing else 0)
            
            trend = existing.get("risk_trend", [])
            trend.append(risk_score)
            # Keep last 20 emails trend
            trend = trend[-20:]
            
            avg_score = sum(trend) / len(trend)
            
            updates = {
                "total_emails_scanned": total,
                "safe_emails_count": safe,
                "phishing_emails_count": phish,
                "average_risk_score": avg_score,
                "risk_trend": trend,
                "last_seen_at": now
            }
            await self.collection.update_one(
                {"_id": self._to_oid(existing["_id"])},
                {"$set": updates}
            )
            existing.update(updates)
            return existing
        else:
            # Create new record
            record_data = {
                "sender_email": email_clean,
                "total_emails_scanned": 1,
                "safe_emails_count": 0 if is_phishing else 1,
                "phishing_emails_count": 1 if is_phishing else 0,
                "average_risk_score": risk_score,
                "risk_trend": [risk_score],
                "last_seen_at": now
            }
            result = await self.collection.insert_one(record_data)
            record_data["_id"] = str(result.inserted_id)
            return record_data
