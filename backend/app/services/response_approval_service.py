import logging
import secrets
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from bson import ObjectId

from app.database.connection import db_manager

logger = logging.getLogger("guardianmail.response_approval_service")

HIGH_RISK_ACTIONS = {"ISOLATE_HOST", "RESET_CREDENTIAL", "REVOKE_SESSION"}

class ResponseApprovalService:
    async def get_decision(self, organization_id: str, id_str: str) -> Optional[Dict[str, Any]]:
        """Retrieve decision scoped to tenant, handling lazy expiration."""
        db = db_manager.db
        decision = await db["response_decisions"].find_one({
            "_id": ObjectId(id_str),
            "organization_id": organization_id,
            "soft_delete": {"$ne": True}
        })
        if not decision:
            return None

        # Lazy expiration handling
        now = datetime.now(timezone.utc)
        status = decision.get("status")
        expires_at = decision.get("expires_at")
        
        # If expires_at is set, check if it has passed
        if status == "PENDING_APPROVAL" and expires_at:
            # Check if aware or naive datetime
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if now > expires_at:
                await db["response_decisions"].update_one(
                    {"_id": ObjectId(id_str)},
                    {"$set": {"status": "EXPIRED", "updated_at": now}}
                )
                await db["audit_logs"].insert_one({
                    "organization_id": organization_id,
                    "user_id": "system",
                    "action": "RESPONSE_APPROVAL_EXPIRED",
                    "details": {
                        "decision_id": id_str,
                        "recommended_action": decision.get("recommended_action")
                    },
                    "created_at": now
                })
                decision["status"] = "EXPIRED"

        return decision

    async def request_approval(self, organization_id: str, decision_id: str, user_id: str) -> Dict[str, Any]:
        """Initiate human approval request, transition status and schedule expiration limit."""
        db = db_manager.db
        decision = await self.get_decision(organization_id, decision_id)
        if not decision:
            raise ValueError("Decision context not found")

        current_status = decision.get("status")
        if current_status not in ["DRAFT", "RECOMMENDED"]:
            raise ValueError(f"State transition rejected: Decision must be in DRAFT or RECOMMENDED status, got '{current_status}'")

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=1)

        result = await db["response_decisions"].update_one(
            {"_id": ObjectId(decision_id), "status": current_status},
            {"$set": {
                "status": "PENDING_APPROVAL",
                "requested_by": user_id,
                "requested_at": now,
                "expires_at": expires_at,
                "updated_at": now
            }}
        )

        if result.modified_count == 0:
            raise ValueError("Concurrent modification detected: status has changed")

        # Log audit trail event
        await db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": user_id,
            "action": "RESPONSE_APPROVAL_REQUESTED",
            "details": {
                "decision_id": decision_id,
                "recommended_action": decision.get("recommended_action")
            },
            "created_at": now
        })

        decision["status"] = "PENDING_APPROVAL"
        decision["requested_by"] = user_id
        decision["requested_at"] = now
        decision["expires_at"] = expires_at
        decision["_id"] = str(decision["_id"])
        return decision

    async def approve_recommendation(self, organization_id: str, decision_id: str, user_id: str, comment: Optional[str] = None) -> Dict[str, Any]:
        """Approve recommendation, enforce separation of duties, and generate secure authorization token."""
        db = db_manager.db
        decision = await self.get_decision(organization_id, decision_id)
        if not decision:
            raise ValueError("Decision context not found")

        if decision.get("status") != "PENDING_APPROVAL":
            raise ValueError(f"State transition rejected: Decision must be in PENDING_APPROVAL status, got '{decision.get('status')}'")

        action = decision.get("recommended_action")
        
        # Enforce Separation of Duties / Four-Eyes Principle for high-risk actions
        if action in HIGH_RISK_ACTIONS:
            creator = decision.get("created_by")
            requester = decision.get("requested_by")
            if user_id in [creator, requester]:
                await db["audit_logs"].insert_one({
                    "organization_id": organization_id,
                    "user_id": user_id,
                    "action": "RESPONSE_APPROVAL_TRANSITION_REJECTED",
                    "details": {
                        "decision_id": decision_id,
                        "reason": "SEPARATION_OF_DUTIES_VIOLATION",
                        "action_type": action
                    },
                    "created_at": datetime.now(timezone.utc)
                })
                raise ValueError("Separation of duties required: requester cannot approve high-risk containment actions")

        # Generate secure authorization token secret and ID
        token_secret = secrets.token_urlsafe(32)
        token_id = str(uuid.uuid4())
        token_hash = hashlib.sha256(token_secret.encode()).hexdigest()

        now = datetime.now(timezone.utc)
        token_expires = now + timedelta(minutes=10)

        update_doc = {
            "status": "APPROVED",
            "approved_by": user_id,
            "approved_at": now,
            "approval_comment": comment,
            "authorization_id": token_id,
            "authorization_hash": token_hash,
            "authorization_issued_at": now,
            "authorization_expires_at": token_expires,
            "authorization_consumed_at": None,
            "updated_at": now
        }

        # Atomic Compare-And-Swap check status
        result = await db["response_decisions"].update_one(
            {"_id": ObjectId(decision_id), "status": "PENDING_APPROVAL"},
            {"$set": update_doc}
        )

        if result.modified_count == 0:
            raise ValueError("Concurrent modification detected: status is no longer PENDING_APPROVAL")

        # Log audits
        await db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": user_id,
            "action": "RESPONSE_APPROVED",
            "details": {
                "decision_id": decision_id,
                "approved_by": user_id,
                "recommended_action": action
            },
            "created_at": now
        })
        await db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": "system",
            "action": "RESPONSE_AUTHORIZATION_ISSUED",
            "details": {
                "decision_id": decision_id,
                "authorization_id": token_id,
                "expires_at": token_expires.isoformat()
            },
            "created_at": now
        })

        decision.update(update_doc)
        decision["authorization_secret"] = token_secret # Returned strictly once
        decision["_id"] = str(decision["_id"])
        return decision

    async def reject_recommendation(self, organization_id: str, decision_id: str, user_id: str, reason: str) -> Dict[str, Any]:
        """Reject recommendation and record analyst justification reason."""
        if not reason or not reason.strip():
            raise ValueError("Rejection reason is required and cannot be empty")

        db = db_manager.db
        decision = await self.get_decision(organization_id, decision_id)
        if not decision:
            raise ValueError("Decision context not found")

        if decision.get("status") != "PENDING_APPROVAL":
            raise ValueError(f"State transition rejected: Decision must be in PENDING_APPROVAL status, got '{decision.get('status')}'")

        now = datetime.now(timezone.utc)
        update_doc = {
            "status": "REJECTED",
            "rejected_by": user_id,
            "rejected_at": now,
            "rejection_reason": reason,
            "updated_at": now
        }

        result = await db["response_decisions"].update_one(
            {"_id": ObjectId(decision_id), "status": "PENDING_APPROVAL"},
            {"$set": update_doc}
        )

        if result.modified_count == 0:
            raise ValueError("Concurrent modification detected: status is no longer PENDING_APPROVAL")

        # Log audit trail event
        await db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": user_id,
            "action": "RESPONSE_REJECTED",
            "details": {
                "decision_id": decision_id,
                "rejected_by": user_id,
                "reason": reason
            },
            "created_at": now
        })

        decision.update(update_doc)
        decision["_id"] = str(decision["_id"])
        return decision

    async def cancel_approval(self, organization_id: str, decision_id: str, user_id: str) -> Dict[str, Any]:
        """Cancel pending approval request."""
        db = db_manager.db
        decision = await self.get_decision(organization_id, decision_id)
        if not decision:
            raise ValueError("Decision context not found")

        if decision.get("status") != "PENDING_APPROVAL":
            raise ValueError(f"State transition rejected: Decision must be in PENDING_APPROVAL status, got '{decision.get('status')}'")

        now = datetime.now(timezone.utc)
        result = await db["response_decisions"].update_one(
            {"_id": ObjectId(decision_id), "status": "PENDING_APPROVAL"},
            {"$set": {
                "status": "CANCELLED",
                "updated_at": now
            }}
        )

        if result.modified_count == 0:
            raise ValueError("Concurrent modification detected: status is no longer PENDING_APPROVAL")

        # Log audit trail event
        await db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": user_id,
            "action": "RESPONSE_APPROVAL_CANCELLED",
            "details": {
                "decision_id": decision_id,
                "cancelled_by": user_id
            },
            "created_at": now
        })

        decision["status"] = "CANCELLED"
        decision["updated_at"] = now
        decision["_id"] = str(decision["_id"])
        return decision

    async def validate_token(
        self,
        organization_id: str,
        decision_id: str,
        recommendation_version: int,
        recommended_action: str,
        playbook_id: str,
        token_id: str,
        token_secret: str
    ) -> Dict[str, Any]:
        """Validate secure authorization token context, bounds, and parameters."""
        db = db_manager.db
        decision = await db["response_decisions"].find_one({
            "_id": ObjectId(decision_id),
            "organization_id": organization_id,
            "soft_delete": {"$ne": True}
        })
        if not decision:
            return {"valid": False, "reason": "Decision context not found"}

        # 1. Status Check
        if decision.get("status") != "APPROVED":
            return {"valid": False, "reason": f"Decision is not in APPROVED state, got '{decision.get('status')}'"}

        # 2. Expiration Check
        now = datetime.now(timezone.utc)
        auth_expires = decision.get("authorization_expires_at")
        if auth_expires:
            if auth_expires.tzinfo is None:
                auth_expires = auth_expires.replace(tzinfo=timezone.utc)
            if now > auth_expires:
                return {"valid": False, "reason": "Authorization token has expired"}

        # 3. Replay Check (Consumption check)
        if decision.get("authorization_consumed_at") is not None:
            return {"valid": False, "reason": "Authorization token already consumed"}

        # 4. Token ID matching
        if decision.get("authorization_id") != token_id:
            return {"valid": False, "reason": "Token ID mismatch"}

        # 5. Cryptographic signature check
        provided_hash = hashlib.sha256(token_secret.encode()).hexdigest()
        if decision.get("authorization_hash") != provided_hash:
            return {"valid": False, "reason": "Cryptographic secret validation mismatch"}

        # 6. Parameter Bindings checks
        if decision.get("recommendation_version", 1) != recommendation_version:
            return {"valid": False, "reason": "Recommendation version mismatch"}
        if decision.get("recommended_action") != recommended_action:
            return {"valid": False, "reason": "Recommended action mismatch"}
        if decision.get("recommended_playbook_id") != playbook_id:
            return {"valid": False, "reason": "Recommended playbook ID mismatch"}

        return {"valid": True}

    async def consume_token(
        self,
        organization_id: str,
        decision_id: str,
        recommendation_version: int,
        recommended_action: str,
        playbook_id: str,
        token_id: str,
        token_secret: str
    ) -> Dict[str, Any]:
        """Atomically validate and mark token as consumed to prevent double-spending replay attacks."""
        db = db_manager.db
        
        # Enforce validation checks
        validation = await self.validate_token(
            organization_id=organization_id,
            decision_id=decision_id,
            recommendation_version=recommendation_version,
            recommended_action=recommended_action,
            playbook_id=playbook_id,
            token_id=token_id,
            token_secret=token_secret
        )

        if not validation["valid"]:
            # Log authorization rejected audit event
            await db["audit_logs"].insert_one({
                "organization_id": organization_id,
                "user_id": "system",
                "action": "RESPONSE_AUTHORIZATION_REJECTED",
                "details": {
                    "decision_id": decision_id,
                    "authorization_id": token_id,
                    "reason": validation["reason"]
                },
                "created_at": datetime.now(timezone.utc)
            })
            raise ValueError(f"Invalid authorization: {validation['reason']}")

        # Atomic token consumption update
        now = datetime.now(timezone.utc)
        result = await db["response_decisions"].update_one(
            {
                "_id": ObjectId(decision_id),
                "organization_id": organization_id,
                "status": "APPROVED",
                "authorization_id": token_id,
                "authorization_consumed_at": None,
                "soft_delete": {"$ne": True}
            },
            {"$set": {"authorization_consumed_at": now}}
        )

        if result.modified_count == 0:
            await db["audit_logs"].insert_one({
                "organization_id": organization_id,
                "user_id": "system",
                "action": "RESPONSE_AUTHORIZATION_REJECTED",
                "details": {
                    "decision_id": decision_id,
                    "authorization_id": token_id,
                    "reason": "CONCURRENT_CONSUMPTION_REPLAY_ATTACK"
                },
                "created_at": now
            })
            raise ValueError("Replay protection triggered: Token has already been consumed concurrently")

        # Log consumption success
        await db["audit_logs"].insert_one({
            "organization_id": organization_id,
            "user_id": "system",
            "action": "RESPONSE_AUTHORIZATION_CONSUMED",
            "details": {
                "decision_id": decision_id,
                "authorization_id": token_id,
                "consumed_at": now.isoformat()
            },
            "created_at": now
        })

        return {"consumed": True, "consumed_at": now}

response_approval_service = ResponseApprovalService()
