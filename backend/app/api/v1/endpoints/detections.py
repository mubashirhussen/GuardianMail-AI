from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from app.api.dependencies.tenant import get_tenant_context, RequirePermission
from app.core.tenant_context import TenantContext
from app.services.detection_service import detection_service
from app.services.grc_service import grc_service
from bson import ObjectId

router = APIRouter()

class DetectionCreateRequest(BaseModel):
    rule_id: str = Field(..., min_length=3)
    name: str = Field(..., min_length=3)
    description: str
    severity: str = "MEDIUM"
    confidence: str = "MEDIUM"
    data_sources: List[str] = []
    conditions: Dict[str, Any] = {}
    time_window: int = 60
    mitre_attack_techniques: List[str] = []
    false_positive_guidance: str = ""

class DetectionUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[str] = None
    data_sources: Optional[List[str]] = None
    conditions: Optional[Dict[str, Any]] = None
    time_window: Optional[int] = None
    mitre_attack_techniques: Optional[List[str]] = None
    false_positive_guidance: Optional[str] = None
    change_info: Optional[str] = None

class StatusTransitionRequest(BaseModel):
    status: str

class InvestigationCreateRequest(BaseModel):
    investigation_id: str
    title: str
    priority: str = "medium"
    entities: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []

@router.get("/detections", response_model=List[Dict[str, Any]])
async def list_detections(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    data_source: Optional[str] = None,
    author: Optional[str] = None,
    search: Optional[str] = None,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """List detection rule templates scoping organization tenant ID."""
    try:
        filters = {}
        if status:
            filters["status"] = status
        if severity:
            filters["severity"] = severity
        if data_source:
            filters["data_source"] = data_source
        if author:
            filters["author"] = author
        if search:
            filters["search"] = search

        return await detection_service.list_rules_filtered(context.organization_id, filters)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/detections", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_detection(
    payload: DetectionCreateRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Create a new detection rule template initializing status to DRAFT."""
    try:
        data = payload.model_dump()
        return await detection_service.create_detection_rule(context.organization_id, data, context.user_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ==============================================================================
# PRODUCTION DETECTION EXECUTION ENGINE API (E11.3)
# ==============================================================================

from app.services.detection_execution_service import detection_execution_service

@router.get("/detections/findings", response_model=List[Dict[str, Any]])
async def list_detection_findings(
    limit: int = 100,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Retrieve normalized production detection findings."""
    try:
        return await detection_execution_service.finding_repo.get_findings_by_org(context.organization_id, limit)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/detections/findings/{finding_id}", response_model=Dict[str, Any])
async def get_detection_finding(
    finding_id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Inspect individual finding and evidence context."""
    try:
        finding = await detection_execution_service.finding_repo.get_by_org_and_id(context.organization_id, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Detection finding not found")
        return finding
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/detections/execution-stats", response_model=Dict[str, Any])
async def get_execution_stats(
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Fetch operational health metrics (processed count, matches, FPs rate, latency stats)."""
    try:
        return await detection_execution_service.get_execution_stats(context.organization_id)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/detections/{id}", response_model=Dict[str, Any])
async def get_detection(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Retrieve full details of a rule along with version history and audit trails."""
    try:
        return await detection_service.get_rule_with_history(context.organization_id, id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.patch("/detections/{id}", response_model=Dict[str, Any])
async def update_detection(
    id: str,
    payload: DetectionUpdateRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Update rule and increment its version."""
    try:
        data = payload.model_dump(exclude_unset=True)
        return await detection_service.update_detection_rule(context.organization_id, id, data, context.user_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/detections/{id}/enable", response_model=Dict[str, Any])
async def enable_detection(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Transition rule status to ACTIVE."""
    try:
        return await detection_service.change_rule_status(context.organization_id, id, "ACTIVE", context.user_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/detections/{id}/disable", response_model=Dict[str, Any])
async def disable_detection(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Transition rule status to DISABLED."""
    try:
        return await detection_service.change_rule_status(context.organization_id, id, "DISABLED", context.user_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/detections/{id}/status", response_model=Dict[str, Any])
async def change_detection_status(
    id: str,
    payload: StatusTransitionRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Transition rule state validating allowed paths strictly."""
    try:
        return await detection_service.change_rule_status(context.organization_id, id, payload.status, context.user_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/detections/{id}/versions", response_model=List[Dict[str, Any]])
async def get_detection_versions(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """List rule versions."""
    try:
        return await detection_service.version_repo.get_versions_by_rule(context.organization_id, id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/detections/{id}/test", response_model=List[Dict[str, Any]])
async def test_detection_rule(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Replay rules conditions over telemetry partition windows to calculate alerts counts."""
    try:
        return await detection_service.execute_rule_historical(context.organization_id, id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ==============================================================================
# E11.5 ENTERPRISE INVESTIGATION & CORRELATION API
# ==============================================================================

from app.services.investigation_service import investigation_service, VALID_STATUSES, VALID_PRIORITIES

class InvestigationUpdateRequest(BaseModel):
    title: Optional[str] = Field(None, min_length=3)
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    severity: Optional[str] = None
    assigned_to: Optional[str] = None

class EvidenceAddRequest(BaseModel):
    evidence_type: str
    source_id: str

class NoteAddRequest(BaseModel):
    content: str = Field(..., min_length=5, max_length=10000)

@router.get("/investigations", response_model=List[Dict[str, Any]])
async def list_investigations(
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """List security investigation cases mapped to organizational scope."""
    try:
        return await investigation_service.inv_repo.get_by_org(context.organization_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/investigations", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_investigation(
    payload: InvestigationCreateRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Initiate a new threat investigation case file."""
    try:
        # Create investigation document
        inv_doc = {
            "organization_id": context.organization_id,
            "investigation_id": payload.investigation_id,
            "title": payload.title,
            "description": "Investigation Case File Initiated",
            "status": "OPEN",
            "priority": payload.priority.upper() if payload.priority.upper() in VALID_PRIORITIES else "MEDIUM",
            "severity": "MEDIUM",
            "created_by": context.user_id,
            "assigned_to": None,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "closed_at": None,
            "soft_delete": False
        }
        res = await investigation_service.inv_repo.create(inv_doc)
        inv_doc["_id"] = str(res["_id"])

        # Populate initial timeline
        await investigation_service.db["audit_logs"].insert_one({
            "organization_id": context.organization_id,
            "action": "INVESTIGATION_CREATED",
            "actor": context.user_id,
            "details": {"investigation_id": inv_doc["investigation_id"], "title": payload.title},
            "timestamp": datetime.utcnow(),
            "soft_delete": False
        })

        # Save entities as evidence links
        for ent in payload.entities:
            ent_type = ent.get("type", "USER")
            val = ent.get("value")
            if val:
                await investigation_service.add_evidence(
                    org_id=context.organization_id,
                    investigation_id=inv_doc["investigation_id"],
                    evidence_type=ent_type,
                    source_id=val,
                    analyst_id=context.user_id,
                    bypass_validation=True
                )

        # Save evidence as evidence links
        for ev in payload.evidence:
            ev_type = ev.get("type", "SECURITY_EVENT").upper()
            if ev_type == "THREAT_INTEL":
                ev_type = "THREAT_INTELLIGENCE"
            elif ev_type == "SYSLOG":
                ev_type = "SECURITY_EVENT"
            
            src_id = ev.get("description") or "MOCK_SOURCE_ID"
            await investigation_service.add_evidence(
                org_id=context.organization_id,
                investigation_id=inv_doc["investigation_id"],
                evidence_type=ev_type,
                source_id=src_id,
                analyst_id=context.user_id,
                bypass_validation=True
            )

        return inv_doc
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/investigations/{id}", response_model=Dict[str, Any])
async def get_investigation_details(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Retrieve full workspace detail including timelines and correlated relationships."""
    try:
        data = await investigation_service.get_investigation_workspace(context.organization_id, id)
        if not data:
            raise HTTPException(status_code=404, detail="Investigation case not found")
        return data
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.patch("/investigations/{id}", response_model=Dict[str, Any])
async def update_investigation(
    id: str,
    payload: InvestigationUpdateRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Update investigation properties and enforce status transition validations."""
    try:
        data = payload.model_dump(exclude_unset=True)
        return await investigation_service.update_investigation(
            org_id=context.organization_id,
            investigation_id=id,
            update_data=data,
            analyst_id=context.user_id
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/investigations/{id}/evidence", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def add_evidence(
    id: str,
    payload: EvidenceAddRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Link external security events or assets to the workspace evidence list."""
    try:
        return await investigation_service.add_evidence(
            org_id=context.organization_id,
            investigation_id=id,
            evidence_type=payload.evidence_type,
            source_id=payload.source_id,
            analyst_id=context.user_id
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/investigations/{id}/evidence/{evidence_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_evidence(
    id: str,
    evidence_id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Unlink evidence reference from investigation workspace."""
    try:
        await investigation_service.remove_evidence(
            org_id=context.organization_id,
            investigation_id=id,
            evidence_id=evidence_id,
            analyst_id=context.user_id
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/investigations/{id}/notes", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def add_note(
    id: str,
    payload: NoteAddRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Create analyst notes linked to investigation container."""
    try:
        return await investigation_service.add_note(
            org_id=context.organization_id,
            investigation_id=id,
            content=payload.content,
            analyst_id=context.user_id
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/investigations/{id}/correlate", response_model=Dict[str, Any])
async def run_correlation(
    id: str,
    use_async: bool = False,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Trigger the correlation engine over linked entities (synchronously or asynchronously via Celery)."""
    try:
        if use_async:
            from app.workers.tasks import run_investigation_correlation_task
            run_investigation_correlation_task.delay(context.organization_id, id)
            return {"status": "PENDING", "message": "Async correlation scheduled"}
        else:
            return await investigation_service.correlate_investigation(context.organization_id, id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/investigations/{id}/graph", response_model=Dict[str, Any])
async def get_investigation_attack_graph(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Generate dynamic attack graph relationships matching entities context."""
    try:
        return await detection_service.generate_attack_graph(context.organization_id, id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/investigations/{id}/ai-summary", response_model=Dict[str, Any])
async def get_investigation_ai_summary(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Retrieve Copilot RAG summaries distinguishing facts from AI models inferences."""
    try:
        return await detection_service.generate_ai_investigation_summary(context.organization_id, id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/investigations/{id}/soar", response_model=Dict[str, Any])
async def handoff_investigation_to_soar(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Trigger incident SOAR remediation response actions."""
    try:
        inv = await detection_service.investigation_repo.get_by_org_and_id(context.organization_id, id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        
        # Simulate E6 handoff trigger
        return {
            "status": "triggered",
            "remediation_workflow_id": f"SOAR-{uuid.uuid4().hex[:6].upper()}",
            "remediation_actions": ["Isolate Device", "Reset User Credentials"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/investigations/{id}/grc", response_model=Dict[str, Any])
async def save_investigation_as_compliance_evidence(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Export investigation timelines and verdicts to GRC compliance repository."""
    try:
        inv = await detection_service.investigation_repo.get_by_org_and_id(context.organization_id, id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        
        # Insert evidence log into GRC collection
        evidence_doc = {
            "organization_id": context.organization_id,
            "control_id": "CTRL-INVESTIGATION-AUDIT",
            "evidence_type": "security_investigation_audit_log",
            "source": f"Telemetry Case File {id}",
            "content_hash": hashlib.sha256(str(inv).encode()).hexdigest(),
            "created_at": datetime.utcnow(),
            "collected_at": datetime.utcnow(),
            "owner_id": context.user_id,
            "status": "active",
            "soft_delete": False
        }
        await grc_service.evidence_repo.collection.insert_one(evidence_doc)
        return {"status": "exported", "evidence_id": str(evidence_doc["_id"])}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

import hashlib
import uuid

# ==============================================================================
# DETECTION TESTING & VALIDATION API (E11.2)
# ==============================================================================

from app.services.detection_testing_service import detection_testing_service
from app.workers.tasks import run_detection_test_task

class TestCaseSchema(BaseModel):
    input_event: Dict[str, Any]
    expected_match: bool
    expected_severity: Optional[str] = None
    expected_technique: Optional[str] = None

class DetectionTestCreateRequest(BaseModel):
    name: str = Field(..., min_length=3)
    description: Optional[str] = None
    test_type: str = "controlled_event"
    version_number: Optional[int] = None
    test_cases: List[TestCaseSchema] = []
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    max_events: Optional[int] = 100

class CompareVersionsRequest(BaseModel):
    v1: int
    v2: int

@router.post("/detections/{id}/tests", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_detection_test(
    id: str,
    payload: DetectionTestCreateRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Create a new detection rule test configuration."""
    try:
        data = payload.model_dump()
        return await detection_testing_service.create_test(context.organization_id, id, data, context.user_id)
    except HTTPException as e:
        raise e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/detections/{id}/tests", response_model=List[Dict[str, Any]])
async def list_detection_tests(
    id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """List all test configurations associated with a specific rule."""
    try:
        return await detection_testing_service.list_tests(context.organization_id, id)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/detections/{id}/tests/{test_id}", response_model=Dict[str, Any])
async def get_detection_test(
    id: str,
    test_id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """View details of a specific test config."""
    doc = await detection_testing_service.get_test(context.organization_id, test_id)
    if not doc or doc.get("rule_id") != id:
        raise HTTPException(status_code=404, detail="Detection test not found")
    return doc

@router.post("/detections/{id}/tests/{test_id}/run", response_model=Dict[str, Any])
async def run_detection_test(
    id: str,
    test_id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Trigger execution of a test run (sync for controlled event/dataset, async Celery for historical replay)."""
    try:
        test = await detection_testing_service.get_test(context.organization_id, test_id)
        if not test or test.get("rule_id") != id:
            raise HTTPException(status_code=404, detail="Detection test not found")
        
        test_type = test.get("test_type", "controlled_event")
        if test_type == "historical_replay":
            # Update test status in database to PENDING (or RUNNING) so client knows it was queued
            await detection_testing_service.test_repo.collection.update_one(
                {"_id": ObjectId(test_id)},
                {"$set": {"status": "PENDING", "updated_at": datetime.utcnow()}}
            )
            # Dispatch async Celery worker task
            run_detection_test_task.delay(context.organization_id, test_id, context.user_id)
            return {"status": "queued", "message": "Historical replay test dispatched to background Celery worker queue."}
        else:
            # Sync execution for controlled event / dataset
            return await detection_testing_service.execute_test_lifecycle(context.organization_id, test_id, context.user_id)
    except HTTPException as e:
        raise e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/detections/{id}/tests/{test_id}/cancel", response_model=Dict[str, Any])
async def cancel_detection_test(
    id: str,
    test_id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.manage"))
):
    """Request cancellation of an active test execution."""
    try:
        test = await detection_testing_service.get_test(context.organization_id, test_id)
        if not test or test.get("rule_id") != id:
            raise HTTPException(status_code=404, detail="Detection test not found")
        return await detection_testing_service.cancel_test(context.organization_id, test_id, context.user_id)
    except HTTPException as e:
        raise e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/detections/{id}/tests/{test_id}/results", response_model=List[Dict[str, Any]])
async def get_detection_test_results(
    id: str,
    test_id: str,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Retrieve outcome metrics results for a test."""
    try:
        test = await detection_testing_service.get_test(context.organization_id, test_id)
        if not test or test.get("rule_id") != id:
            raise HTTPException(status_code=404, detail="Detection test not found")
        return await detection_testing_service.result_repo.get_by_test(context.organization_id, test_id)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/detections/{id}/tests/{test_id}/matches", response_model=List[Dict[str, Any]])
async def get_detection_test_matches(
    id: str,
    test_id: str,
    result_id: Optional[str] = None,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Retrieve detailed matching events recorded during evaluation."""
    try:
        test = await detection_testing_service.get_test(context.organization_id, test_id)
        if not test or test.get("rule_id") != id:
            raise HTTPException(status_code=404, detail="Detection test not found")
        
        if not result_id:
            # Get latest result id
            results = await detection_testing_service.result_repo.get_by_test(context.organization_id, test_id)
            if not results:
                return []
            result_id = results[0]["_id"]

        return await detection_testing_service.match_repo.get_by_result(context.organization_id, result_id)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/detections/{id}/compare-versions", response_model=Dict[str, Any])
async def compare_rule_versions(
    id: str,
    payload: CompareVersionsRequest,
    context: TenantContext = Depends(RequirePermission("telemetry.read"))
):
    """Compare test run stats between two specific versions of a rule."""
    try:
        return await detection_testing_service.compare_versions(context.organization_id, id, payload.v1, payload.v2)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



