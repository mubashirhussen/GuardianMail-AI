import logging
from typing import Optional, Dict, Any, List
from bson import ObjectId
from app.core.tenant_context import TenantContext
from app.database.connection import db_manager
from app.repositories.threat_intelligence_repo import ThreatIndicatorRepository, ThreatCampaignRepository
from app.repositories.security_policy_repo import SecurityPolicyRepository

logger = logging.getLogger("guardianmail.copilot_tools")

class CopilotTools:
    """Safe, tenant-isolated tools library for the AI Security Copilot agent."""

    @staticmethod
    async def search_threat_indicators(context: TenantContext, query: str) -> List[Dict[str, Any]]:
        """Search threat indicator database collections matching values under tenant organization or global scope."""
        repo = ThreatIndicatorRepository(db_manager.db)
        # Filters indicators by tenant org ID or global (None) scope
        return await repo.search_indicators(
            org_id=context.organization_id,
            indicator_type=None,
            severity=None,
            status="ACTIVE",
            source=None,
            limit=20
        )

    @staticmethod
    async def get_indicator(context: TenantContext, indicator_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve single threat indicator validating multi-tenant boundary checks."""
        repo = ThreatIndicatorRepository(db_manager.db)
        ioc = await repo.get(indicator_id)
        if not ioc:
            return None
        if ioc.get("organization_id") and ioc.get("organization_id") != context.organization_id:
            logger.warning(f"Tenant isolation breach attempt by user {context.user_id} accessing indicator {indicator_id}")
            return None
        return ioc

    @staticmethod
    async def search_campaigns(context: TenantContext, query: str) -> List[Dict[str, Any]]:
        """Retrieve threat campaigns list under active organization scope."""
        repo = ThreatCampaignRepository(db_manager.db)
        return await repo.get_by_org(context.organization_id)

    @staticmethod
    async def get_campaign(context: TenantContext, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve campaign details by ID validating tenant isolation boundaries."""
        repo = ThreatCampaignRepository(db_manager.db)
        camp = await repo.get(campaign_id)
        if not camp:
            return None
        if camp.get("organization_id") and camp.get("organization_id") != context.organization_id:
            return None
        return camp

    @staticmethod
    async def get_incident(context: TenantContext, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve single scanned email incident checking ownership."""
        db = db_manager.db
        doc = await db["emails"].find_one({"_id": ObjectId(incident_id)})
        if not doc:
            return None
        # Verify ownership / tenant context organization ID matching
        if doc.get("organization_id") and doc.get("organization_id") != context.organization_id:
            return None
        doc["_id"] = str(doc["_id"])
        return doc

    @staticmethod
    async def get_investigation(context: TenantContext, investigation_id: str) -> Optional[Dict[str, Any]]:
        """Fetch investigation incident record with validation."""
        db = db_manager.db
        doc = await db["incidents"].find_one({"_id": ObjectId(investigation_id)})
        if not doc:
            return None
        if doc.get("organization_id") and doc.get("organization_id") != context.organization_id:
            return None
        doc["_id"] = str(doc["_id"])
        return doc

    @staticmethod
    async def get_security_policy(context: TenantContext, policy_type: str) -> List[Dict[str, Any]]:
        """Query policy engine rules matching active category."""
        repo = SecurityPolicyRepository(db_manager.db)
        return await repo.get_active_policies_by_org_and_type(context.organization_id, policy_type)

    @staticmethod
    async def get_mitre_technique(context: TenantContext, technique_id: str) -> Optional[Dict[str, Any]]:
        """Fetch MITRE technique attributes."""
        db = db_manager.db
        doc = await db["threat_techniques"].find_one({"technique_id": technique_id.upper().strip()})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    @staticmethod
    async def search_users(context: TenantContext, email_query: str) -> List[Dict[str, Any]]:
        """List matched organization users list."""
        db = db_manager.db
        # Query memberships for target org first
        cursor = db["organization_memberships"].find({"organization_id": context.organization_id})
        members = await cursor.to_list(length=100)
        uids = [ObjectId(m["user_id"]) for m in members]
        
        users_cursor = db["users"].find({
            "_id": {"$in": uids},
            "email": {"$regex": email_query, "$options": "i"}
        })
        users = await users_cursor.to_list(length=10)
        for u in users:
            u["_id"] = str(u["_id"])
            u.pop("password", None)
            u.pop("totp_secret", None)
        return users
