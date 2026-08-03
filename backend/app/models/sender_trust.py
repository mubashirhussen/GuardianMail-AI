from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class SenderTrustRecord(BaseModel):
    """Sender trust database record tracking history and trend behavior."""
    id: Optional[str] = Field(None, alias="_id")
    sender_email: str
    total_emails_scanned: int = 0
    safe_emails_count: int = 0
    phishing_emails_count: int = 0
    average_risk_score: float = 0.0
    risk_trend: List[float] = Field(default_factory=list)
    last_seen_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = {
        "populate_by_name": True
    }
