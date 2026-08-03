import pytest
import io
import json
import zipfile
from httpx import AsyncClient
from app.database.connection import db_manager
from app.workers.tasks import generate_forensic_bundle_task, scheduled_reminder_task
from bson import ObjectId

@pytest.mark.asyncio
async def test_incident_response_full_workflow(client: AsyncClient):
    # 1. Register and login investigator user
    register_payload = {
        "email": "ir_analyst@example.com",
        "username": "ir_analyst",
        "password": "secure_ir_password_123",
        "full_name": "Incident Responder Analyst",
        "role": "admin"
    }
    await client.post("/api/v1/auth/register", json=register_payload)
    
    login_resp = await client.post("/api/v1/auth/login", json={
        "email": "ir_analyst@example.com",
        "password": "secure_ir_password_123"
    })
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Inject mock malicious email record into MongoDB
    mock_email = {
        "user_id": "ir_analyst@example.com",
        "subject": "URGENT: Password reset required immediately!",
        "from_address": "fraud@paypal-spoof.com",
        "soft_delete": False,
        "date": "2026-07-29T12:00:00Z",
        "gmail_account": "ir_analyst@example.com",
        "attachments": [{"filename": "invoice_malicious.pdf", "size_bytes": 102400}],
        "urls": [{"url": "http://paypal-spoof.com/reset"}],
        "analysis": {
            "verdict": "PHISHING",
            "risk_score": 0.85,
            "confidence_score": 0.90,
            "indicators": [
                {"indicator": "Credential harvesting keyword", "severity": "HIGH", "detail": "Contains 'password reset' and 'verify credentials'", "type": "phishing"},
                {"indicator": "Urgent pressure keyword", "severity": "MEDIUM", "detail": "Contains 'immediately'", "type": "phishing"}
            ],
            "timeline": [
                {"event": "PARSED", "description": "Email headers and MIME structures parsed successfully.", "timestamp": "2026-07-29T12:05:00Z"}
            ],
            "explanation": "High risk brand impersonation and credential harvesting lure detected."
        }
    }
    
    insert_res = await db_manager.db["emails"].insert_one(mock_email)
    email_id = str(insert_res.inserted_id)
    
    # 3. Create Incident via Endpoint
    create_resp = await client.post("/api/v1/incidents", json={
        "email_id": email_id,
        "priority": "HIGH",
        "tags": ["phishing", "paypal"],
        "custom_labels": {"department": "Finance"},
        "investigation_notes": "Starting deep forensic analysis."
    }, headers=headers)
    assert create_resp.status_code == 201
    incident = create_resp.json()
    assert incident["status"] == "Detected"
    assert incident["threat_severity"] == "CRITICAL"  # score 0.85 maps to CRITICAL
    assert incident["affected_email"] == email_id
    incident_id = incident["incident_id"]
    
    # 4. Timeline verification & manual insertion
    timeline_resp = await client.get(f"/api/v1/incidents/{incident_id}/timeline", headers=headers)
    assert timeline_resp.status_code == 200
    timeline = timeline_resp.json()
    assert len(timeline) >= 2
    assert any(evt["event"] == "INCIDENT_DETECTED" for evt in timeline)
    
    # Insert custom timeline event
    add_evt_resp = await client.post(
        f"/api/v1/incidents/{incident_id}/timeline?event=INVESTIGATING&description=Analyst starting packet captures.",
        headers=headers
    )
    assert add_evt_resp.status_code == 200
    
    # Verify timeline updated
    updated_timeline_resp = await client.get(f"/api/v1/incidents/{incident_id}/timeline", headers=headers)
    assert len(updated_timeline_resp.json()) == len(timeline) + 1
    assert updated_timeline_resp.json()[-1]["event"] == "INVESTIGATING"
    
    # 5. Search Incidents filters
    search_resp = await client.get(
        f"/api/v1/incidents/search?incident_id={incident_id[:8]}&status=Detected&severity=CRITICAL",
        headers=headers
    )
    assert search_resp.status_code == 200
    search_results = search_resp.json()
    assert len(search_results) >= 1
    assert any(res["incident_id"] == incident_id for res in search_results)
    
    # 6. Update status and tags
    update_resp = await client.put(f"/api/v1/incidents/{incident_id}", json={
        "status": "Investigating",
        "priority": "HIGH",
        "tags": ["phishing", "paypal", "escalated"]
    }, headers=headers)
    assert update_resp.status_code == 200
    assert update_resp.json()["status"] == "Investigating"
    assert "escalated" in update_resp.json()["tags"]
    
    # 7. Add Investigator Notes
    note_resp = await client.post(f"/api/v1/incidents/{incident_id}/notes?content=Found related phishing domains in internal logs.", headers=headers)
    assert note_resp.status_code == 200
    assert note_resp.json()["content"] == "Found related phishing domains in internal logs."
    
    notes_list_resp = await client.get(f"/api/v1/incidents/{incident_id}/notes", headers=headers)
    assert len(notes_list_resp.json()) == 1
    
    # 8. Recovery checklist verification
    checklist_resp = await client.get(f"/api/v1/incidents/{incident_id}/recovery", headers=headers)
    assert checklist_resp.status_code == 200
    checklist = checklist_resp.json()
    assert len(checklist) > 0
    # Credential indicators trigger MFA and PASSWORD recovery items
    assert any(item["action_type"] == "MFA" for item in checklist)
    action_id = checklist[0]["_id"]
    
    # Toggle recovery item completion
    toggle_resp = await client.post(f"/api/v1/incidents/recovery/{action_id}/toggle?is_completed=true", headers=headers)
    assert toggle_resp.status_code == 200
    assert toggle_resp.json()["action"]["is_completed"] is True
    
    # 9. Complaint preparation center
    complaint_resp = await client.post(
        f"/api/v1/incidents/{incident_id}/complaint?template_type=cybercrime_portal&recipient_entity=FBI-IC3",
        headers=headers
    )
    assert complaint_resp.status_code == 200
    complaint = complaint_resp.json()["complaint_draft"]
    assert "OFFICIAL SECURITY INCIDENT REPORT DRAFT" in complaint["body_content"]
    assert complaint["recipient_entity"] == "FBI-IC3"
    
    # 10. Direct PDF report download
    pdf_resp = await client.post(f"/api/v1/incidents/{incident_id}/report", headers=headers)
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert len(pdf_resp.content) > 0
    
    # 11. Evidence forensic ZIP compilation and download workflow
    evidence_trigger = await client.post(f"/api/v1/incidents/{incident_id}/evidence", headers=headers)
    assert evidence_trigger.status_code == 200
    
    download_resp = await client.get(f"/api/v1/incidents/{incident_id}/download", headers=headers)
    assert download_resp.status_code == 200
    assert download_resp.headers["content-type"] == "application/zip"
    
    # Inspect packaged ZIP bundle
    zip_buf = io.BytesIO(download_resp.content)
    with zipfile.ZipFile(zip_buf) as z:
        namelist = z.namelist()
        assert "report.pdf" in namelist
        assert "report.json" in namelist
        assert "indicators.csv" in namelist
        assert "manifest.json" in namelist
        
        # Verify JSON report content
        report_data = json.loads(z.read("report.json").decode("utf-8"))
        assert report_data["incident"]["incident_id"] == incident_id
        
        # Verify Manifest hashes matching
        manifest_data = json.loads(z.read("manifest.json").decode("utf-8"))
        assert manifest_data["incident_id"] == incident_id
        assert "report.pdf" in manifest_data["files"]
        assert "sha256" in manifest_data["files"]["report.pdf"]
        
@pytest.mark.asyncio
async def test_incident_response_celery_jobs():
    # Test Celery scheduled_reminder_task in eager mode
    # Inject complaint draft in DB first
    complaint_doc = {
        "incident_id": "INC-TEST-CELERY",
        "template_type": "internal_incident",
        "recipient_entity": "SOC Team",
        "subject": "Incident notification",
        "body_content": "Draft Content",
        "status": "Draft",
        "soft_delete": False,
        "created_at": "2026-07-29T12:00:00Z"
    }
    res = await db_manager.db["complaint_drafts"].insert_one(complaint_doc)
    doc_id = str(res.inserted_id)
    
    task_res = scheduled_reminder_task.delay(doc_id).get()
    assert task_res["status"] == "success"
    assert task_res["complaint_id"] == doc_id
    
    # Verify DB update
    updated_doc = await db_manager.db["complaint_drafts"].find_one({"_id": ObjectId(doc_id)})
    assert updated_doc["reminder_triggered"] is True
