from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from app.api.dependencies.auth import get_current_active_user
from app.models.user import UserInDB
from app.repositories.email_repo import EmailRepository
from app.database.connection import db_manager
from app.services.decision_intelligence import DecisionIntelligenceService
from app.services.intel_providers.implementations import DNSWhoisProvider, GoogleSafeBrowsingProvider, AbuseIPDBProvider

router = APIRouter()

async def get_email_repo() -> EmailRepository:
    if db_manager.db is None:
         raise RuntimeError("Database connection not ready.")
    return EmailRepository(db_manager.db)

@router.post("/analyze")
async def analyze_threat_intelligence(
    payload: Dict[str, str],
    current_user: UserInDB = Depends(get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Correlate security flags with external threat feeds and compile decision results."""
    email_id = payload.get("email_id")
    if not email_id:
         raise HTTPException(status_code=400, detail="Missing email_id parameter.")
         
    email_rec = await email_repo.get(email_id)
    if not email_rec:
         raise HTTPException(status_code=404, detail="Email record not found.")
         
    if email_rec.get("user_id") != str(current_user.id):
         raise HTTPException(status_code=403, detail="Forbidden.")
         
    decision = await DecisionIntelligenceService.evaluate_threat_intelligence(email_rec, db_manager.db)
    
    # Save the decision intelligence results to the email document in MongoDB
    updates = {
        "threat_intel": decision,
        "processing_status": "completed"
    }
    await email_repo.update(email_id, updates)
    return decision

@router.get("/domain/{domain}")
async def get_domain_threat_info(
    domain: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Retrieve registrar lookup details and domain WHOIS registration age metrics."""
    whois = DNSWhoisProvider()
    res = await whois.lookup(domain)
    return res

@router.get("/url")
async def get_url_threat_info(
    url: str = Query(..., min_length=4),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Retrieve reputation lookup parameters for a specific URL indicator."""
    safe_browsing = GoogleSafeBrowsingProvider()
    res = await safe_browsing.lookup(url)
    return res

@router.get("/ip/{ip}")
async def get_ip_threat_info(
    ip: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Retrieve IP abuse score and geolocations info."""
    abuse_ipdb = AbuseIPDBProvider()
    res = await abuse_ipdb.lookup(ip)
    return res

@router.get("/reputation/{sender}")
async def get_sender_reputation_info(
    sender: str,
    current_user: UserInDB = Depends(get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Check historical sender counts and return reputation score averages."""
    user_id = str(current_user.id)
    query = {
        "user_id": user_id,
        "from_address": sender.lower().strip()
    }
    emails = await email_repo.get_multi(query=query, limit=100)
    safe_count = sum(1 for e in emails if e.get("analysis", {}).get("verdict") == "SAFE")
    return {
        "sender": sender,
        "historical_count": len(emails),
        "safe_count": safe_count,
        "reputation": "high" if safe_count >= 5 else "unknown"
    }

@router.get("/report/{scan_id}")
async def get_scan_report(
    scan_id: str,
    current_user: UserInDB = Depends(get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Fetch complete decision intelligence report for a scanned email."""
    email_rec = await email_repo.get(scan_id)
    if not email_rec:
         raise HTTPException(status_code=404, detail="Email record not found.")
         
    if email_rec.get("user_id") != str(current_user.id):
         raise HTTPException(status_code=403, detail="Forbidden.")
         
    return email_rec.get("threat_intel") or {}

@router.get("/campaigns")
async def get_active_campaigns(
    current_user: UserInDB = Depends(get_current_active_user),
    email_repo: EmailRepository = Depends(get_email_repo)
):
    """Retrieve list of identified active threat campaigns."""
    user_id = str(current_user.id)
    # Search for all emails containing threat_intel details that display a campaign
    query = {
        "user_id": user_id,
        "threat_intel.campaign.detected": True
    }
    emails = await email_repo.get_multi(query=query, limit=50)
    campaigns_list = []
    for e in emails:
         ti = e.get("threat_intel", {})
         campaigns_list.append({
             "email_id": str(e["_id"]),
             "subject": e.get("subject"),
             "campaign_name": ti.get("campaign", {}).get("name"),
             "evidence": ti.get("campaign", {}).get("evidence", [])
         })
    return campaigns_list
