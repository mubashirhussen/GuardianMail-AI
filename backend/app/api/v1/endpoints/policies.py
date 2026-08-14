from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from app.api.dependencies.auth import get_current_active_user
from app.api.dependencies.tenant import get_tenant_context, RequirePermission
from app.core.tenant_context import TenantContext
from app.models.user import UserInDB
from app.models.security_policy import SecurityPolicy, PolicyVersion, PolicyApproval, PolicySimulation
from app.repositories.security_policy_repo import (
    SecurityPolicyRepository, PolicyVersionRepository, PolicyApprovalRepository,
    PolicySimulationRepository, PolicyAuditRepository
)
from app.database.connection import db_manager
from app.services.policy_engine import policy_engine
from bson import ObjectId

router = APIRouter()

# Schema definitions
class PolicyRuleCreate(BaseModel):
    conditions: List[Dict[str, Any]]
    action: str
    description: str

class PolicyCreate(BaseModel):
    policy_type: str
    rules: List[PolicyRuleCreate]
    department: Optional[str] = None
    team: Optional[str] = None
    user_id: Optional[str] = None

class PolicyUpdate(BaseModel):
    rules: List[PolicyRuleCreate]

class SimulationRequest(BaseModel):
    policy_type: str
    payload: Dict[str, Any]

class ApprovalAction(BaseModel):
    action: str # approve, reject
    reason: Optional[str] = None

# Repos dependencies
async def get_policy_repos():
    db = db_manager.db
    if not db:
        raise RuntimeError("Database connection not ready.")
    return {
        "policy": SecurityPolicyRepository(db),
        "version": PolicyVersionRepository(db),
        "approval": PolicyApprovalRepository(db),
        "simulation": PolicySimulationRepository(db),
        "audit": PolicyAuditRepository(db)
    }

@router.get("/policies", response_model=List[Dict[str, Any]])
async def list_policies(
    context: TenantContext = Depends(RequirePermission("policies.read")),
    repos = Depends(get_policy_repos)
):
    """List active policies for the tenant organization."""
    return await repos["policy"].get_active_policies_by_org(context.organization_id)

@router.post("/policies", response_model=Dict[str, Any])
async def create_policy(
    payload: PolicyCreate,
    context: TenantContext = Depends(RequirePermission("policies.create")),
    repos = Depends(get_policy_repos)
):
    """Creates a new security policy draft (Tenant Isolated)."""
    now = datetime.now(timezone.utc)
    policy_doc = {
        "organization_id": context.organization_id,
        "department": payload.department,
        "team": payload.team,
        "user_id": payload.user_id,
        "policy_type": payload.policy_type,
        "rules": [r.model_dump() for r in payload.rules],
        "version": 1,
        "status": "draft",
        "created_by": context.user_id,
        "created_at": now,
        "updated_at": now
    }
    
    created = await repos["policy"].create(policy_doc)
    created["_id"] = str(created["_id"])
    
    # Audit log creation
    await repos["audit"].create({
        "organization_id": context.organization_id,
        "actor_id": context.user_id,
        "policy_id": created["_id"],
        "action": "POLICY_CREATED",
        "details": {"type": payload.policy_type},
        "timestamp": now
    })
    
    return created

@router.get("/policies/{id}", response_model=Dict[str, Any])
async def get_policy(
    id: str,
    context: TenantContext = Depends(RequirePermission("policies.read")),
    repos = Depends(get_policy_repos)
):
    """Fetch specific policy with IDOR check."""
    policy = await repos["policy"].get(id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if policy.get("organization_id") != context.organization_id:
        raise HTTPException(status_code=403, detail="Access denied (tenant isolation).")
    return policy

@router.patch("/policies/{id}", response_model=Dict[str, Any])
async def update_policy(
    id: str,
    payload: PolicyUpdate,
    context: TenantContext = Depends(RequirePermission("policies.update")),
    repos = Depends(get_policy_repos)
):
    """Update policy rules, producing a version draft."""
    policy = await repos["policy"].get(id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if policy.get("organization_id") != context.organization_id:
        raise HTTPException(status_code=403, detail="Access denied (tenant isolation).")
        
    now = datetime.now(timezone.utc)
    
    # Snapshot current active version
    version_doc = {
        "policy_id": id,
        "version": policy["version"],
        "rules": policy["rules"],
        "status": policy["status"],
        "created_by": policy["created_by"],
        "created_at": policy.get("updated_at") or now,
        "reason": "Incremental update"
    }
    await repos["version"].create(version_doc)
    
    new_version = policy["version"] + 1
    rules_dict = [r.model_dump() for r in payload.rules]
    
    await repos["policy"].collection.update_one(
        {"_id": ObjectId(id)},
        {
            "$set": {
                "rules": rules_dict,
                "version": new_version,
                "status": "draft", # resets to draft until approved
                "updated_at": now
            }
        }
    )
    
    # Audit log update
    await repos["audit"].create({
        "organization_id": context.organization_id,
        "actor_id": context.user_id,
        "policy_id": id,
        "action": "POLICY_UPDATED",
        "details": {"new_version": new_version},
        "timestamp": now
    })
    
    updated = await repos["policy"].get(id)
    return updated

@router.post("/policies/{id}/submit", response_model=Dict[str, Any])
async def submit_policy(
    id: str,
    context: TenantContext = Depends(RequirePermission("policies.update")),
    repos = Depends(get_policy_repos)
):
    """Submit policy draft for approval."""
    policy = await repos["policy"].get(id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if policy.get("organization_id") != context.organization_id:
        raise HTTPException(status_code=403, detail="Access denied.")
        
    now = datetime.now(timezone.utc)
    approval_payload = {
        "policy_id": id,
        "requested_by": context.user_id,
        "requested_at": now,
        "status": "pending"
    }
    approval = await repos["approval"].create(approval_payload)
    approval["_id"] = str(approval["_id"])
    
    await repos["policy"].collection.update_one(
        {"_id": ObjectId(id)},
        {"$set": {"status": "review"}}
    )
    
    return approval

@router.post("/policies/{id}/approve", response_model=Dict[str, Any])
async def approve_policy(
    id: str,
    payload: ApprovalAction,
    context: TenantContext = Depends(RequirePermission("policies.approve")),
    repos = Depends(get_policy_repos)
):
    """Approve or reject a submitted draft with Separation of Duties verification."""
    policy = await repos["policy"].get(id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if policy.get("organization_id") != context.organization_id:
        raise HTTPException(status_code=403, detail="Access denied.")
        
    now = datetime.now(timezone.utc)
    
    # 1. Fetch pending approval request
    approval_req = await repos["approval"].collection.find_one({
        "policy_id": id,
        "status": "pending"
    })
    if not approval_req:
        raise HTTPException(status_code=400, detail="No pending approval request found for this policy.")
        
    # 2. Enforce separation of duty (CTO signature bypass prevention)
    if approval_req["requested_by"] == context.user_id:
        raise HTTPException(
            status_code=403, 
            detail="Separation of Duties violation: A user cannot approve their own policy changes."
        )
        
    status_verdict = "approved" if payload.action == "approve" else "rejected"
    policy_status = "active" if payload.action == "approve" else "draft"
    
    await repos["approval"].collection.update_one(
        {"_id": approval_req["_id"]},
        {
            "$set": {
                "approved_by": context.user_id,
                "approved_at": now,
                "status": status_verdict,
                "reason": payload.reason
            }
        }
    )
    
    await repos["policy"].collection.update_one(
        {"_id": ObjectId(id)},
        {"$set": {"status": policy_status}}
    )
    
    # Invalidate cache if approved/active
    if payload.action == "approve":
         await policy_engine.invalidate_policy_cache(context.organization_id, policy["policy_type"])
         
    # Audit log
    await repos["audit"].create({
        "organization_id": context.organization_id,
        "actor_id": context.user_id,
        "policy_id": id,
        "action": f"POLICY_APPROVED_{status_verdict.upper()}",
        "details": {"reason": payload.reason},
        "timestamp": now
    })
    
    return {"status": status_verdict}

@router.post("/policies/{id}/activate")
async def activate_policy(
    id: str,
    context: TenantContext = Depends(RequirePermission("policies.activate")),
    repos = Depends(get_policy_repos)
):
    """Enable / activate configured policy rules."""
    policy = await repos["policy"].get(id)
    if not policy or policy.get("organization_id") != context.organization_id:
        raise HTTPException(status_code=404, detail="Policy not found")
        
    now = datetime.now(timezone.utc)
    await repos["policy"].collection.update_one(
        {"_id": ObjectId(id)},
        {"$set": {"status": "active", "updated_at": now}}
    )
    await policy_engine.invalidate_policy_cache(context.organization_id, policy["policy_type"])
    return {"detail": "Policy activated."}

@router.post("/policies/{id}/disable")
async def disable_policy(
    id: str,
    context: TenantContext = Depends(RequirePermission("policies.activate")),
    repos = Depends(get_policy_repos)
):
    """Disable active policy."""
    policy = await repos["policy"].get(id)
    if not policy or policy.get("organization_id") != context.organization_id:
        raise HTTPException(status_code=404, detail="Policy not found")
        
    now = datetime.now(timezone.utc)
    await repos["policy"].collection.update_one(
        {"_id": ObjectId(id)},
        {"$set": {"status": "disabled", "updated_at": now}}
    )
    await policy_engine.invalidate_policy_cache(context.organization_id, policy["policy_type"])
    return {"detail": "Policy disabled."}

@router.get("/policies/{id}/versions")
async def list_versions(
    id: str,
    context: TenantContext = Depends(RequirePermission("policies.read")),
    repos = Depends(get_policy_repos)
):
    """Retrieve immutable snapshots history."""
    policy = await repos["policy"].get(id)
    if not policy or policy.get("organization_id") != context.organization_id:
        raise HTTPException(status_code=404, detail="Policy not found")
        
    return await repos["version"].get_by_policy_id(id)

@router.post("/policies/simulate")
async def simulate_policy(
    payload: SimulationRequest,
    context: TenantContext = Depends(RequirePermission("policies.simulate")),
    repos = Depends(get_policy_repos)
):
    """Simulate proposed policy evaluation outcome (No destructive operations)."""
    verdict = await policy_engine.evaluate(payload.policy_type, context, payload.payload)
    
    # Store simulation log
    sim_log = {
        "organization_id": context.organization_id,
        "policy_type": payload.policy_type,
        "payload": payload.payload,
        "decision": verdict["decision"],
        "explanation": verdict["explanation"],
        "simulated_at": datetime.now(timezone.utc)
    }
    await repos["simulation"].create(sim_log)
    return verdict

@router.get("/policies/posture")
async def get_security_posture(
    context: TenantContext = Depends(RequirePermission("policies.read")),
    db = Depends(lambda: db_manager.db)
):
    """Calculate and return organization security posture score."""
    if not db:
        raise HTTPException(status_code=500, detail="Database connection failed")
        
    score = 45 # baseline score
    recommendations = []
    
    # 1. SSO Check
    idp = await db["identity_providers"].find_one({"organization_id": context.organization_id, "enabled": True})
    if idp:
        score += 20
    else:
        recommendations.append("Configure SSO Identity Provider to authenticate corporate users.")
        
    # 2. MFA Check
    users_cursor = db["organization_memberships"].find({"organization_id": context.organization_id})
    members = await users_cursor.to_list(length=100)
    if members:
        user_ids = [m["user_id"] for m in members]
        mfa_users = await db["users"].count_documents({"_id": {"$in": [ObjectId(uid) for uid in user_ids]}, "mfa_enabled": True})
        mfa_ratio = mfa_users / len(members)
        if mfa_ratio >= 0.8:
            score += 20
        else:
            score += int(mfa_ratio * 20)
            recommendations.append("Enforce MFA enrollment across your organization users.")
    else:
        recommendations.append("Enforce MFA enrollment across your organization users.")
        
    # 3. Custom active security policies check
    policy_count = await db["security_policies"].count_documents({
        "organization_id": context.organization_id,
        "status": "active"
    })
    if policy_count >= 3:
        score += 15
    else:
        score += policy_count * 5
        recommendations.append("Configure Email, Attachment, and URL Security policies.")
        
    return {
        "score": min(score, 100),
        "recommendations": recommendations,
        "disclaimer": "This score is for internal security posture estimation and does not represent formal compliance certification."
    }
