"""
Repository for managing cryptographically protected verification challenges.
Supports single-use 6-digit OTP issuance, HMAC protection, expiration, attempt caps, and resend cooldowns.
"""

import hmac
import hashlib
from typing import Any, Dict, Optional, Tuple
from datetime import datetime, timezone, timedelta
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository
from app.config.settings import settings

def hash_verification_code(code: str, identifier: str, purpose: str) -> str:
    """
    Computes a keyed HMAC-SHA256 representation of the verification code.
    Prevents rainbow-table brute force attacks on 6-digit codes and binds to destination & purpose.
    """
    key = settings.SECRET_KEY.encode("utf-8")
    message = f"{identifier.strip().lower()}:{purpose.strip().lower()}:{code.strip()}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()

class VerificationRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "verification_challenges")

    @staticmethod
    def normalize_identifier(identifier: str) -> str:
        ident = identifier.strip()
        if "@" in ident:
            return ident.lower()
        return ident

    async def get_latest_challenge(self, identifier: str, purpose: str) -> Optional[Dict[str, Any]]:
        norm_id = self.normalize_identifier(identifier)
        doc = await self.collection.find_one(
            {"identifier": norm_id, "purpose": purpose},
            sort=[("created_at", -1)]
        )
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def check_resend_cooldown(self, identifier: str, purpose: str) -> int:
        """
        Returns seconds remaining if currently under resend cooldown, else 0.
        """
        latest = await self.get_latest_challenge(identifier, purpose)
        if not latest:
            return 0
            
        resend_at = latest.get("resend_available_at")
        if not resend_at:
            return 0
            
        if resend_at.tzinfo is None:
            resend_at = resend_at.replace(tzinfo=timezone.utc)
            
        now = datetime.now(timezone.utc)
        if now < resend_at:
            return max(1, int((resend_at - now).total_seconds()))
        return 0

    async def create_challenge(
        self,
        identifier: str,
        identifier_type: str,
        purpose: str,
        code: str,
        user_id: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        cooldown_seconds: Optional[int] = None,
        max_attempts: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Invalidates previous active challenges for (identifier, purpose) and stores a new one.
        """
        now = datetime.now(timezone.utc)
        norm_id = self.normalize_identifier(identifier)
        ttl = ttl_seconds or settings.AUTH_CODE_TTL_SECONDS
        cooldown = cooldown_seconds or settings.AUTH_RESEND_COOLDOWN_SECONDS
        max_att = max_attempts or settings.AUTH_MAX_VERIFICATION_ATTEMPTS

        # Invalidate any existing active unconsumed challenges for this destination & purpose
        await self.collection.update_many(
            {"identifier": norm_id, "purpose": purpose, "consumed_at": None},
            {"$set": {"consumed_at": now}}
        )

        hashed = hash_verification_code(code, norm_id, purpose)
        doc = {
            "identifier": norm_id,
            "identifier_type": identifier_type,
            "purpose": purpose,
            "hashed_code": hashed,
            "attempts_count": 0,
            "max_attempts": max_att,
            "expires_at": now + timedelta(seconds=ttl),
            "resend_available_at": now + timedelta(seconds=cooldown),
            "consumed_at": None,
            "created_at": now,
            "challenge_metadata": {"user_id": user_id} if user_id else {}
        }

        created = await self.create(doc)
        created["_id"] = str(created["_id"])
        return created

    async def verify_challenge(
        self,
        identifier: str,
        purpose: str,
        code: str
    ) -> Tuple[bool, str]:
        """
        Verifies code against latest active unconsumed challenge.
        Enforces expiration, max attempts, and constant-time HMAC check.
        """
        now = datetime.now(timezone.utc)
        norm_id = self.normalize_identifier(identifier)

        challenge = await self.collection.find_one(
            {"identifier": norm_id, "purpose": purpose, "consumed_at": None},
            sort=[("created_at", -1)]
        )

        if not challenge:
            return False, "No active verification challenge found. Please request a new code."

        # Expiry check
        expires_at = challenge.get("expires_at")
        if expires_at:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if now > expires_at:
                await self.collection.update_one(
                    {"_id": challenge["_id"]},
                    {"$set": {"consumed_at": now}}
                )
                return False, "Verification code has expired. Please request a new code."

        # Attempts cap check
        attempts_count = challenge.get("attempts_count", 0)
        max_attempts = challenge.get("max_attempts", 5)
        if attempts_count >= max_attempts:
            await self.collection.update_one(
                {"_id": challenge["_id"]},
                {"$set": {"consumed_at": now}}
            )
            return False, "Too many incorrect attempts. This code has been invalidated. Please request a new code."

        # Validate code using constant time comparison
        expected_hash = hash_verification_code(code, norm_id, purpose)
        is_match = hmac.compare_digest(expected_hash, challenge.get("hashed_code", ""))

        if not is_match:
            new_attempts = attempts_count + 1
            if new_attempts >= max_attempts:
                await self.collection.update_one(
                    {"_id": challenge["_id"]},
                    {"$set": {"attempts_count": new_attempts, "consumed_at": now}}
                )
                return False, "Too many incorrect attempts. This code has been invalidated."
            else:
                await self.collection.update_one(
                    {"_id": challenge["_id"]},
                    {"$set": {"attempts_count": new_attempts}}
                )
                remaining = max_attempts - new_attempts
                return False, f"Invalid verification code. {remaining} attempt(s) remaining."

        # Success - consume code
        await self.collection.update_one(
            {"_id": challenge["_id"]},
            {"$set": {"consumed_at": now}}
        )
        return True, "Verification successful"
