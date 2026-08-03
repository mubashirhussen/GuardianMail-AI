import io
import csv
import json
import zipfile
import hashlib
import logging
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson.objectid import ObjectId

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from app.models.incident import (
    IncidentRecord, IncidentStatus, IncidentPriority,
    IncidentTimelineRecord, RecoveryActionRecord,
    InvestigationNotesRecord, ReportHistoryRecord
)
from app.repositories.incident_repo import (
    IncidentRepository, IncidentTimelineRepository,
    EvidencePackagesRepository, ComplaintDraftsRepository,
    RecoveryActionsRepository, InvestigationNotesRepository,
    ReportHistoryRepository
)
from app.repositories.email_repo import EmailRepository
from app.repositories.device_repo import DeviceRepository
from app.services.observability import SystemObservabilityService
from app.database.cache import cache_manager

logger = logging.getLogger(__name__)

class IncidentResponseService:
    @staticmethod
    def _clean_dict(d: Any) -> Any:
        """Helper to recursively convert ObjectId and datetimes to serializable types."""
        if isinstance(d, dict):
            return {k: IncidentResponseService._clean_dict(v) for k, v in d.items()}
        elif isinstance(d, list):
            return [IncidentResponseService._clean_dict(v) for v in d]
        elif hasattr(d, "isoformat"):
            return d.isoformat()
        elif isinstance(d, ObjectId):
            return str(d)
        else:
            return d

    @staticmethod
    async def create_incident(
        db: AsyncIOMotorDatabase,
        email_id: str,
        priority: IncidentPriority = IncidentPriority.MEDIUM,
        tags: List[str] = None,
        custom_labels: Dict[str, str] = None,
        investigation_notes: str = "",
        user_id: str = "system"
    ) -> IncidentRecord:
        """Escalate a flagged email thread into an official incident investigation (Incident Engine)."""
        email_repo = EmailRepository(db)
        incident_repo = IncidentRepository(db)
        timeline_repo = IncidentTimelineRepository(db)
        recovery_repo = RecoveryActionsRepository(db)
        
        email_record = await email_repo.get(email_id)
        if not email_record:
            raise ValueError(f"Email record with ID {email_id} not found")
            
        # Check if incident already exists for this email
        existing = await incident_repo.get_multi(query={"affected_email": email_id}, limit=1)
        if existing:
            existing[0]["_id"] = str(existing[0]["_id"])
            return IncidentRecord(**existing[0])
            
        analysis = email_record.get("analysis", {})
        verdict = analysis.get("verdict", "UNKNOWN")
        risk_score = analysis.get("risk_score", 0.0)
        
        # Calculate severity based on risk score
        if risk_score >= 0.75:
            severity = "CRITICAL"
        elif risk_score >= 0.50:
            severity = "HIGH"
        elif risk_score >= 0.25:
            severity = "MEDIUM"
        else:
            severity = "LOW"
            
        incident_num = f"INC-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:8].upper()}"
        
        # Determine affected user and entities
        affected_user_val = email_record.get("user_id") or "unknown_user"
        gmail_acct = email_record.get("gmail_account") or email_record.get("to_address")
        
        # Map attachments and URLs
        attachments = [att.get("filename") for att in email_record.get("attachments", []) if att.get("filename")]
        urls = [url.get("url") for url in email_record.get("urls", []) if url.get("url")]
        
        # Pull devices linked to the user context
        device_repo = DeviceRepository(db)
        devices = await device_repo.get_multi(query={"user_id": affected_user_val}, limit=10)
        device_ids = [str(d.get("_id", d.get("id"))) for d in devices]
        
        now = datetime.now(timezone.utc)
        
        incident_dict = {
            "incident_id": incident_num,
            "status": IncidentStatus.DETECTED,
            "detection_time": now,
            "threat_category": verdict,
            "threat_severity": severity,
            "confidence": analysis.get("confidence_score", 0.85),
            "affected_email": email_id,
            "affected_user": affected_user_val,
            "related_devices": device_ids,
            "related_gmail_account": gmail_acct,
            "related_attachments": attachments,
            "related_urls": urls,
            "tags": tags or [],
            "priority": priority,
            "custom_labels": custom_labels or {},
            "investigation_notes": investigation_notes,
            "created_at": now,
            "updated_at": now
        }
        
        created = await incident_repo.create(incident_dict)
        
        # Generate initial timeline events (Timeline Engine)
        initial_events = [
            {"event": "EMAIL_RECEIVED", "description": "Phishing message received by mail client.", "timestamp": email_record.get("date", now)},
            {"event": "SCAN_COMPLETED", "description": f"Multi-Engine threat scans completed with score {int(risk_score * 100)}/100.", "timestamp": now},
            {"event": "INCIDENT_DETECTED", "description": "Incident escalated and registered in incident response workspace.", "timestamp": now}
        ]
        
        # Incorporate existing parser timeline events if present
        for event in analysis.get("timeline", []):
            initial_events.append({
                "event": event.get("event", "SYSTEM_LOG"),
                "description": event.get("description", ""),
                "timestamp": event.get("timestamp") or now
            })
            
        for evt in initial_events:
            await timeline_repo.create({
                "incident_id": incident_num,
                "event": evt["event"],
                "timestamp": evt["timestamp"],
                "description": evt["description"]
            })
            
        # Build Recovery Checklist (Incident Recovery Assistant)
        indicators_lower = [ind.get("indicator", "").lower() for ind in analysis.get("indicators", [])]
        has_creds = any("credential" in ind or "login" in ind or "password" in ind for ind in indicators_lower)
        has_links = len(urls) > 0
        has_attachments = len(attachments) > 0
        
        checklist = []
        if has_creds:
            checklist.append({"action_type": "MFA", "description": "Enable Multi-Factor Authentication (MFA) on affected account."})
            checklist.append({"action_type": "PASSWORD", "description": "Revoke current password and generate a new high-entropy password."})
            checklist.append({"action_type": "SESSION_REVOCATION", "description": "Revoke all active sessions and OAuth grants."})
            checklist.append({"action_type": "SECURITY_QUESTIONS", "description": "Reset account security questions and recovery options."})
        if has_links:
            checklist.append({"action_type": "BANKING_MONITOR", "description": "Monitor associated financial accounts for suspicious charges."})
            checklist.append({"action_type": "OAUTH_DISCONNECT", "description": "Disconnect unknown/suspicious OAuth applications."})
            checklist.append({"action_type": "ACCOUNT_MONITOR", "description": "Check email forwarding rules and automatic filters."})
        if has_attachments:
            checklist.append({"action_type": "MALWARE_SCAN", "description": "Run comprehensive endpoint anti-virus scan on host device."})
            
        checklist.append({"action_type": "SOC_NOTIFY", "description": "Notify enterprise SOC/IT Administrator of email threat."})
        checklist.append({"action_type": "EMPLOYER_CONTACT", "description": "Report incident to employer if sent to corporate address."})
        
        for item in checklist:
            await recovery_repo.create({
                "incident_id": incident_num,
                "action_type": item["action_type"],
                "description": item["description"],
                "is_completed": False,
                "completed_at": None
            })
            
        # Record metric
        SystemObservabilityService.record_incident_lifecycle(IncidentStatus.DETECTED)
        
        created["_id"] = str(created["_id"])
        return IncidentRecord(**created)

    @staticmethod
    async def add_timeline_event(db: AsyncIOMotorDatabase, incident_id: str, event: str, description: str) -> None:
        """Appends chronological events manually or programmatically to an investigation log."""
        timeline_repo = IncidentTimelineRepository(db)
        await timeline_repo.create({
            "incident_id": incident_id,
            "event": event,
            "timestamp": datetime.now(timezone.utc),
            "description": description
        })

    @staticmethod
    async def get_timeline(db: AsyncIOMotorDatabase, incident_id: str) -> List[Dict[str, Any]]:
        """Retrieve chronological timeline events for an incident sorted by time."""
        timeline_repo = IncidentTimelineRepository(db)
        events = await timeline_repo.get_multi(query={"incident_id": incident_id}, sort_by="timestamp", sort_desc=False)
        for e in events:
            e["_id"] = str(e["_id"])
        return events

    @staticmethod
    async def update_incident_status(
        db: AsyncIOMotorDatabase,
        incident_id: str,
        status: IncidentStatus,
        user_id: str = "system"
    ) -> Optional[Dict[str, Any]]:
        """Update incident lifecycle status and log the lifecycle transition event."""
        incident_repo = IncidentRepository(db)
        incidents = await incident_repo.get_multi(query={"incident_id": incident_id}, limit=1)
        if not incidents:
            return None
            
        old_status = incidents[0].get("status")
        if old_status == status:
            return incidents[0]
            
        await incident_repo.update(str(incidents[0]["_id"]), {
            "status": status,
            "updated_at": datetime.now(timezone.utc)
        })
        
        # Log event
        await IncidentResponseService.add_timeline_event(
            db, incident_id, "STATUS_TRANSITION",
            f"Incident lifecycle status transitioned from '{old_status}' to '{status}' by {user_id}."
        )
        
        SystemObservabilityService.record_incident_lifecycle(status)
        
        incidents[0]["status"] = status
        incidents[0]["_id"] = str(incidents[0]["_id"])
        return incidents[0]

    @staticmethod
    def generate_pdf_report(incident: Dict[str, Any], email_record: Dict[str, Any], timeline: List[Dict[str, Any]]) -> bytes:
        """Compile a forensic-grade PDF Investigation Report (PDF Generation)."""
        start_time = datetime.now(timezone.utc)
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        story = []
        
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Heading1'],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#1A365D"),
            spaceAfter=12
        )
        section_style = ParagraphStyle(
            'SectionHeader',
            parent=styles['Heading2'],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#2B6CB0"),
            spaceBefore=12,
            spaceAfter=5
        )
        body_style = ParagraphStyle(
            'DocBody',
            parent=styles['Normal'],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#2D3748")
        )
        
        # Title
        story.append(Paragraph("GUARDIANMAIL AI - FORENSIC SECURITY REPORT", title_style))
        story.append(Spacer(1, 8))
        
        # Core metadata table
        data = [
            [Paragraph("<b>Incident ID:</b>", body_style), Paragraph(incident.get("incident_id", ""), body_style),
             Paragraph("<b>Status:</b>", body_style), Paragraph(incident.get("status", ""), body_style)],
            [Paragraph("<b>Threat Category:</b>", body_style), Paragraph(incident.get("threat_category", ""), body_style),
             Paragraph("<b>Threat Severity:</b>", body_style), Paragraph(incident.get("threat_severity", ""), body_style)],
            [Paragraph("<b>Confidence Score:</b>", body_style), Paragraph(f"{incident.get('confidence', 0.0) * 100:.1f}%", body_style),
             Paragraph("<b>Priority:</b>", body_style), Paragraph(incident.get("priority", ""), body_style)],
            [Paragraph("<b>Affected User:</b>", body_style), Paragraph(incident.get("affected_user", ""), body_style),
             Paragraph("<b>Target Account:</b>", body_style), Paragraph(incident.get("related_gmail_account") or "N/A", body_style)]
        ]
        t = Table(data, colWidths=[100, 160, 80, 160])
        t.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#EDF2F7")),
            ('BACKGROUND', (2,0), (2,-1), colors.HexColor("#EDF2F7")),
            ('PADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(t)
        story.append(Spacer(1, 10))
        
        # Threat intelligence indicators
        story.append(Paragraph("Identified Risk Indicators", section_style))
        analysis = email_record.get("analysis", {})
        indicators = analysis.get("indicators", [])
        if indicators:
            ind_data = [[Paragraph("<b>Indicator Type</b>", body_style), Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Risk Detail Summary</b>", body_style)]]
            for ind in indicators:
                ind_data.append([
                    Paragraph(ind.get("indicator", ""), body_style),
                    Paragraph(ind.get("severity", ""), body_style),
                    Paragraph(ind.get("detail", ""), body_style)
                ])
            ind_table = Table(ind_data, colWidths=[130, 60, 310])
            ind_table.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#EDF2F7")),
                ('PADDING', (0,0), (-1,-1), 4),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ]))
            story.append(ind_table)
        else:
            story.append(Paragraph("No threat indicators logged for this email context.", body_style))
        story.append(Spacer(1, 10))
        
        # Timeline block
        story.append(Paragraph("Incident Timeline Logs", section_style))
        if timeline:
            time_data = [[Paragraph("<b>Timestamp (UTC)</b>", body_style), Paragraph("<b>Event Code</b>", body_style), Paragraph("<b>Description Log Detail</b>", body_style)]]
            for item in timeline:
                ts = item.get("timestamp")
                ts_str = ts.isoformat()[:19] if hasattr(ts, "isoformat") else str(ts)[:19]
                time_data.append([
                    Paragraph(ts_str, body_style),
                    Paragraph(item.get("event", ""), body_style),
                    Paragraph(item.get("description", ""), body_style)
                ])
            time_table = Table(time_data, colWidths=[110, 110, 280])
            time_table.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#EDF2F7")),
                ('PADDING', (0,0), (-1,-1), 4),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ]))
            story.append(time_table)
        else:
            story.append(Paragraph("No chronological timeline event records found.", body_style))
            
        doc.build(story)
        
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        SystemObservabilityService.record_report_gen(duration)
        
        return buffer.getvalue()

    @staticmethod
    async def generate_forensic_bundle(db: AsyncIOMotorDatabase, incident_id: str) -> bytes:
        """Compile PDF, CSV, JSON, manifest files and package them into an integrity-hashed ZIP file (Forensic Bundle)."""
        start_time = datetime.now(timezone.utc)
        
        incident_repo = IncidentRepository(db)
        timeline_repo = IncidentTimelineRepository(db)
        email_repo = EmailRepository(db)
        evidence_repo = EvidencePackagesRepository(db)
        
        incidents = await incident_repo.get_multi(query={"incident_id": incident_id}, limit=1)
        if not incidents:
            raise ValueError(f"Incident with ID {incident_id} not found")
            
        incident = incidents[0]
        timeline = await timeline_repo.get_multi(query={"incident_id": incident_id}, sort_by="timestamp", sort_desc=False)
        email_record = await email_repo.get(incident["affected_email"])
        if not email_record:
            raise ValueError(f"Email record linked to incident {incident_id} not found")
            
        # 1. Generate PDF Report
        pdf_bytes = IncidentResponseService.generate_pdf_report(incident, email_record, timeline)
        
        # 2. Generate JSON Report
        clean_incident = IncidentResponseService._clean_dict(incident)
        clean_timeline = IncidentResponseService._clean_dict(timeline)
        clean_email = IncidentResponseService._clean_dict(email_record)
        
        json_report = {
            "report_version": "1.0.0",
            "generation_timestamp": datetime.now(timezone.utc).isoformat(),
            "incident": clean_incident,
            "timeline": clean_timeline,
            "email_record": clean_email
        }
        json_bytes = json.dumps(json_report, indent=2).encode("utf-8")
        
        # 3. Generate CSV Indicators
        csv_output = io.StringIO()
        writer = csv.writer(csv_output)
        writer.writerow(["indicator", "detail", "severity", "type"])
        analysis = email_record.get("analysis", {})
        for ind in analysis.get("indicators", []):
            writer.writerow([
                ind.get("indicator", ""),
                ind.get("detail", ""),
                ind.get("severity", ""),
                ind.get("type", "")
            ])
        csv_bytes = csv_output.getvalue().encode("utf-8")
        
        # Compute individual SHA-256 hashes
        pdf_hash = hashlib.sha256(pdf_bytes).hexdigest()
        json_hash = hashlib.sha256(json_bytes).hexdigest()
        csv_hash = hashlib.sha256(csv_bytes).hexdigest()
        
        # 4. Generate Manifest with hashes
        manifest = {
            "manifest_version": "1.0.0",
            "incident_id": incident_id,
            "generation_timestamp": datetime.now(timezone.utc).isoformat(),
            "files": {
                "report.pdf": {"size_bytes": len(pdf_bytes), "sha256": pdf_hash},
                "report.json": {"size_bytes": len(json_bytes), "sha256": json_hash},
                "indicators.csv": {"size_bytes": len(csv_bytes), "sha256": csv_hash}
            }
        }
        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
        manifest["manifest_hash_sha256"] = manifest_hash
        
        # Package ZIP Archive
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("report.pdf", pdf_bytes)
            z.writestr("report.json", json_bytes)
            z.writestr("indicators.csv", csv_bytes)
            z.writestr("manifest.json", json.dumps(manifest, indent=2).encode("utf-8"))
            
        zip_bytes = zip_buffer.getvalue()
        zip_hash = hashlib.sha256(zip_bytes).hexdigest()
        
        # Encode ZIP bytes to base64 for MongoDB payload storage
        import base64
        payload_base64 = base64.b64encode(zip_bytes).decode("utf-8")
        
        # Write to EvidencePackages collection
        evidence_record = {
            "email_id": incident["affected_email"],
            "pack_name": f"evidence_{incident_id}.zip",
            "export_format": "zip",
            "content_payload": payload_base64,
            "file_size_bytes": len(zip_bytes),
            "download_url": f"/api/v1/incidents/{incident_id}/download",
            "sha256_hash": zip_hash,
            "manifest": manifest,
            "created_at": datetime.now(timezone.utc)
        }
        
        created_pack = await evidence_repo.create(evidence_record)
        pack_id = str(created_pack["_id"])
        
        # Link pack back to Incident
        await incident_repo.update(str(incident["_id"]), {
            "evidence_pack_id": pack_id,
            "status": IncidentStatus.EVIDENCE_GENERATED,
            "updated_at": datetime.now(timezone.utc)
        })
        
        # Timeline update
        await IncidentResponseService.add_timeline_event(
            db, incident_id, "EVIDENCE_PACKAGED",
            f"Forensic evidence ZIP bundle generated (SHA256: {zip_hash[:10]}...) and signed manifest computed."
        )
        
        # Caching Zip in Redis
        cache_key = f"evidence:zip:{incident_id}"
        await cache_manager.set(cache_key, payload_base64, expire_seconds=300) # cache for 5 minutes
        
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        SystemObservabilityService.record_evidence_gen(duration)
        SystemObservabilityService.record_export()
        
        return zip_bytes

    @staticmethod
    async def generate_complaint_draft(
        db: AsyncIOMotorDatabase,
        incident_id: str,
        template_type: str,
        recipient_entity: str
    ) -> Dict[str, Any]:
        """Automatically draft structured security warnings and incident reporting drafts (Complaint Preparation)."""
        incident_repo = IncidentRepository(db)
        email_repo = EmailRepository(db)
        complaints_repo = ComplaintDraftsRepository(db)
        
        incidents = await incident_repo.get_multi(query={"incident_id": incident_id}, limit=1)
        if not incidents:
            raise ValueError(f"Incident with ID {incident_id} not found")
            
        incident = incidents[0]
        email_record = await email_repo.get(incident["affected_email"])
        if not email_record:
            raise ValueError(f"Email record linked to incident {incident_id} not found")
            
        analysis = email_record.get("analysis", {})
        indicators = [ind.get("indicator") for ind in analysis.get("indicators", [])]
        
        portal_urls = {
            "cybercrime_portal": "https://www.ic3.gov (FBI IC3) or regional cyber crime portal",
            "email_abuse_report": "https://support.google.com/mail/contact/abuse",
            "internal_incident": "Corporate SOC/IT Security Reporting Channel",
        }
        
        now = datetime.now(timezone.utc)
        
        structured_body = (
            f"--- OFFICIAL SECURITY INCIDENT REPORT DRAFT ---\n"
            f"Incident Reference ID : {incident_id}\n"
            f"Target System / User  : {incident.get('affected_user')}\n"
            f"Attacker Source Address: {email_record.get('from_address')}\n"
            f"Email Subject Header  : {email_record.get('subject')}\n"
            f"Assigned Risk Score   : {int(analysis.get('risk_score', 0.0) * 100)}/100\n"
            f"Threat Classification  : {analysis.get('verdict', 'UNKNOWN')}\n"
            f"Triggered Indicators  : {', '.join(indicators) if indicators else 'None'}\n\n"
            f"--- TECHNICAL AUDIT DETAILS ---\n"
            f"Authentication Flags: SPF={email_record.get('spf_status', 'N/A')}\n"
            f"Detected URL Links  : {', '.join(incident.get('related_urls', [])) or 'None'}\n"
            f"Mail Attachment Names: {', '.join(incident.get('related_attachments', [])) or 'None'}\n\n"
            f"--- CYBER INTELLIGENCE EXPLANATION ---\n"
            f"{analysis.get('explanation', 'No detailed analysis summary available.')}\n\n"
            f"--- RECOMMENDED REMEDIATION STEPS ---\n"
            f"1. Do not open or reply to this message.\n"
            f"2. Revoke associated user sessions and verify authentication logs.\n"
            f"3. Purge email thread from mail client repositories.\n\n"
            f"Report Draft created by GuardianMail AI. Draft target portal: {recipient_entity}.\n"
        )
        
        draft_dict = {
            "incident_id": incident_id,
            "template_type": template_type,
            "recipient_entity": recipient_entity,
            "subject": f"Cybersecurity Incident Report: {incident_id} ({incident.get('threat_category')})",
            "body_content": structured_body,
            "status": "Draft",
            "version": 1,
            "version_history": [{"version": 1, "body_content": structured_body, "updated_at": now}],
            "created_at": now,
            "updated_at": now
        }
        
        created = await complaints_repo.create(draft_dict)
        draft_id = str(created["_id"])
        
        # Link draft to Incident
        await incident_repo.update(str(incident["_id"]), {
            "complaint_draft_id": draft_id,
            "status": IncidentStatus.COMPLAINT_DRAFT_READY,
            "updated_at": datetime.now(timezone.utc)
        })
        
        # Add timeline event
        await IncidentResponseService.add_timeline_event(
            db, incident_id, "COMPLAINT_DRAFTED",
            f"Complaint draft generated for submission portal: {recipient_entity} ({template_type})."
        )
        
        SystemObservabilityService.record_complaint_draft()
        
        created["_id"] = draft_id
        return created

    @staticmethod
    async def get_recovery_checklist(db: AsyncIOMotorDatabase, incident_id: str) -> List[Dict[str, Any]]:
        """Retrieve the containment and recovery actions checklist for an incident."""
        recovery_repo = RecoveryActionsRepository(db)
        actions = await recovery_repo.get_multi(query={"incident_id": incident_id}, limit=50)
        for act in actions:
            act["_id"] = str(act["_id"])
        return actions

    @staticmethod
    async def toggle_recovery_action(db: AsyncIOMotorDatabase, action_id: str, is_completed: bool) -> Optional[Dict[str, Any]]:
        """Toggle completeness of containment or remediation workflow item."""
        recovery_repo = RecoveryActionsRepository(db)
        record = await recovery_repo.get(action_id)
        if not record:
            return None
            
        now = datetime.now(timezone.utc) if is_completed else None
        await recovery_repo.update(action_id, {
            "is_completed": is_completed,
            "completed_at": now
        })
        
        record["is_completed"] = is_completed
        record["completed_at"] = now
        record["_id"] = str(record["_id"])
        
        # Log event
        await IncidentResponseService.add_timeline_event(
            db, record["incident_id"], "RECOVERY_ACTION_COMPLETED" if is_completed else "RECOVERY_ACTION_RESET",
            f"Remediation action item '{record['action_type']}' completeness marked as {is_completed}."
        )
        
        return record

    @staticmethod
    async def get_incident_notes(db: AsyncIOMotorDatabase, incident_id: str) -> List[Dict[str, Any]]:
        """Retrieve investigator workspace notes for an incident."""
        notes_repo = InvestigationNotesRepository(db)
        notes = await notes_repo.get_multi(query={"incident_id": incident_id}, sort_by="created_at", sort_desc=True)
        for n in notes:
            n["_id"] = str(n["_id"])
        return notes

    @staticmethod
    async def add_investigator_note(db: AsyncIOMotorDatabase, incident_id: str, investigator_id: str, content: str) -> Dict[str, Any]:
        """Add custom notes or investigation findings into the workspace."""
        notes_repo = InvestigationNotesRepository(db)
        now = datetime.now(timezone.utc)
        note_dict = {
            "incident_id": incident_id,
            "investigator_id": investigator_id,
            "content": content,
            "created_at": now,
            "updated_at": now
        }
        created = await notes_repo.create(note_dict)
        created["_id"] = str(created["_id"])
        
        # Log timeline event
        await IncidentResponseService.add_timeline_event(
            db, incident_id, "NOTE_ADDED",
            f"Investigator {investigator_id} added analysis findings into investigation workspace notes."
        )
        
        return created

    @staticmethod
    async def search_incidents(
        db: AsyncIOMotorDatabase,
        incident_id: Optional[str] = None,
        sender: Optional[str] = None,
        domain: Optional[str] = None,
        threat_type: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        min_risk_score: Optional[float] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Advanced database incident queries with filtering options."""
        incident_repo = IncidentRepository(db)
        
        # Pre-check search cache in Redis
        cache_key_elements = [incident_id, sender, domain, threat_type, severity, status, priority, date_from, date_to, min_risk_score, limit]
        cache_key = "search:" + hashlib.md5(str(cache_key_elements).encode("utf-8")).hexdigest()
        
        cached_data = await cache_manager.get(cache_key)
        if cached_data:
            return cached_data
            
        query: Dict[str, Any] = {}
        
        if incident_id:
            query["incident_id"] = {"$regex": incident_id, "$options": "i"}
        if threat_type:
            query["threat_category"] = threat_type
        if severity:
            query["threat_severity"] = severity
        if status:
            query["status"] = status
        if priority:
            query["priority"] = priority
            
        # Filter by affected email properties (sender address or domain)
        if sender or domain or min_risk_score:
            email_repo = EmailRepository(db)
            email_query: Dict[str, Any] = {}
            if sender:
                email_query["from_address"] = {"$regex": sender, "$options": "i"}
            if domain:
                email_query["sender_domain"] = domain
            if min_risk_score:
                email_query["analysis.risk_score"] = {"$gte": min_risk_score}
                
            emails = await email_repo.get_multi(query=email_query, limit=500)
            email_ids = [str(e.get("_id", e.get("id"))) for e in emails]
            query["affected_email"] = {"$in": email_ids}
            
        # Date range filter
        if date_from or date_to:
            date_filter: Dict[str, Any] = {}
            if date_from:
                date_filter["$gte"] = date_from
            if date_to:
                date_filter["$lte"] = date_to
            query["detection_time"] = date_filter
            
        results = await incident_repo.get_multi(query=query, limit=limit, sort_by="detection_time", sort_desc=True)
        for r in results:
            r["_id"] = str(r["_id"])
            
        # Cache results in Redis for 1 minute
        cleaned = IncidentResponseService._clean_dict(results)
        await cache_manager.set(cache_key, cleaned, expire_seconds=60)
        
        return results
