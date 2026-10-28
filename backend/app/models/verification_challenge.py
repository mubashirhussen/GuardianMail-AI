"""
Verification challenge model representing short-lived, cryptographically protected
one-time identity verification challenges for Email and SMS OTP delivery.
"""

from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from app.models.base import BaseMongoModel

class VerificationChallenge(BaseMongoModel):
    """Document stored in verification_challenges collection."""
    identifier: str = Field(..., description="Normalized email or E.164 phone number")
    identifier_type: str = Field(..., description="email or phone")
    purpose: str = Field(..., description="registration, password_reset, login_step_up, phone_verification")
    hashed_code: str = Field(..., description="HMAC-SHA256 representation of verification code")
    attempts_count: int = Field(default=0, description="Number of failed verification attempts")
    max_attempts: int = Field(default=5, description="Maximum allowed attempts before invalidation")
    expires_at: datetime = Field(..., description="Challenge expiration timestamp")
    resend_available_at: datetime = Field(..., description="Timestamp after which resend is permitted")
    consumed_at: Optional[datetime] = Field(default=None, description="When challenge was successfully redeemed")
    challenge_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Context details (e.g. user_id)")

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }
