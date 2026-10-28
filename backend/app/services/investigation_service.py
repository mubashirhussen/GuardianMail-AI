import logging
import uuid
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from bson import ObjectId

from app.database.connection import db_manager
from app.repositories.investigation_repo import (
    InvestigationRepository, InvestigationEvidenceRepository,
    InvestigationNoteRepository, InvestigationRelationshipRepository
)
from app.repositories.audit_repo import AuditRepository

logger = logging.getLogger(__name__)

VALID_STATUSES = ["DRAFT", "OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]
VALID_PRIORITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
VALID_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Lifecycle transitions state-machine mapping
STATUS_FLOWS = {
    "DRAFT": ["OPEN"],
    "OPEN": ["INVESTIGATING", "CLOSED"],
    "INVESTIGATING": ["CONTAINED", "CLOSED"],
    "CONTAINED": ["RESOLVED", "CLOSED"],
    "RESOLVED": ["CLOSED"],
    "CLOSED": ["OPEN"]  # Re-opening allowed
}

class InvestigationService:
    @property
    def db(self):
        return db_manager.db

    @property
    def inv_repo(self):
        return InvestigationRepository(self.db)

    @property
    def evidence_repo(self):
        return InvestigationEvidenceRepository(self.db)

    @property
    def note_repo(self):
        return InvestigationNoteRepository(self.db)

    @property
    def relation_repo(self):
        return InvestigationRelationshipRepository(self.db)

    @property
    def audit_repo(self):
        return AuditRepository(self.db)

    async def create_investigation(
        self,
        org_id: str,
        title: str,
        description: str,
        priority: str,
        severity: str,
        created_by: str
    ) -> Dict[str, Any]:
        """Create a new threat investigation initialized in DRAFT status."""
        if priority not in VALID_PRIORITIES:
            raise ValueError(f"Invalid priority: {priority}")
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        doc = {
            "organization_id": org_id,
            "title": title,
            "description": description,
            "status": "DRAFT",
            "priority": priority,
            "severity": severity,
            "created_by": created_by,
            "assigned_to": None,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "closed_at": None,
            "soft_delete": False
        }
        res = await self.inv_repo.create(doc)
        res["_id"] = str(res["_id"])

        # Audit log
        await self.audit_repo.collection.insert_one({
            "organization_id": org_id,
            "action": "INVESTIGATION_CREATED",
            "actor": created_by,
            "details": {"investigation_id": res["_id"], "title": title},
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        })
        return res

    async def update_investigation(
        self,
        org_id: str,
        investigation_id: str,
        update_data: Dict[str, Any],
        analyst_id: str
    ) -> Dict[str, Any]:
        """Update investigation details enforcing status transition workflows."""
        inv = await self.inv_repo.get(investigation_id)
        if not inv or inv.get("organization_id") != org_id:
            raise ValueError("Investigation not found")

        current_status = inv.get("status", "DRAFT")
        new_status = update_data.get("status")

        # Enforce lifecycle state machine check
        if new_status and new_status != current_status:
            allowed = STATUS_FLOWS.get(current_status, [])
            if new_status not in allowed:
                raise ValueError(f"Unauthorized state transition from {current_status} to {new_status}")
            
            # Log transition audit
            await self.audit_repo.collection.insert_one({
                "organization_id": org_id,
                "action": "INVESTIGATION_STATUS_CHANGED",
                "actor": analyst_id,
                "details": {
                    "investigation_id": investigation_id,
                    "old_status": current_status,
                    "new_status": new_status
                },
                "timestamp": datetime.now(timezone.utc),
                "soft_delete": False
            })

            if new_status == "CLOSED":
                update_data["closed_at"] = datetime.now(timezone.utc)

        # Enforce validation on severity and priority changes
        if "priority" in update_data and update_data["priority"] not in VALID_PRIORITIES:
            raise ValueError("Invalid priority value")
        if "severity" in update_data and update_data["severity"] not in VALID_SEVERITIES:
            raise ValueError("Invalid severity value")

        update_data["updated_at"] = datetime.now(timezone.utc)
        
        # Auditing metadata updates
        if "assigned_to" in update_data and update_data["assigned_to"] != inv.get("assigned_to"):
            await self.audit_repo.collection.insert_one({
                "organization_id": org_id,
                "action": "INVESTIGATION_ASSIGNED",
                "actor": analyst_id,
                "details": {
                    "investigation_id": investigation_id,
                    "assigned_to": update_data["assigned_to"]
                },
                "timestamp": datetime.now(timezone.utc),
                "soft_delete": False
            })

        await self.inv_repo.collection.update_one(
            {"_id": ObjectId(investigation_id)},
            {"$set": update_data}
        )
        
        updated_inv = await self.inv_repo.get(investigation_id)
        updated_inv["_id"] = str(updated_inv["_id"])
        
        # Log generic update audit
        await self.audit_repo.collection.insert_one({
            "organization_id": org_id,
            "action": "INVESTIGATION_UPDATED",
            "actor": analyst_id,
            "details": {"investigation_id": investigation_id, "fields": list(update_data.keys())},
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        })

        return updated_inv

    async def add_evidence(
        self,
        org_id: str,
        investigation_id: str,
        evidence_type: str,
        source_id: str,
        analyst_id: str,
        bypass_validation: bool = False
    ) -> Dict[str, Any]:
        """Link existing evidence context to the investigation workspace validating tenant boundaries."""
        # Validate parent investigation
        inv = await self.inv_repo.get(investigation_id)
        if not inv or inv.get("organization_id") != org_id:
            # Fallback for E11.1 mock lookup by investigation_id field
            inv_by_id = await self.inv_repo.collection.find_one({
                "organization_id": org_id,
                "investigation_id": investigation_id,
                "soft_delete": False
            })
            if not inv_by_id:
                raise ValueError("Investigation not found")

        # Enforce limits (max 100 evidence references per investigation)
        existing_evidence = await self.evidence_repo.get_by_investigation(org_id, investigation_id)
        if len(existing_evidence) >= 100:
            raise ValueError("Resource limits reached: Maximum of 100 evidence items per investigation allowed.")

        # Check if already linked
        duplicate = await self.evidence_repo.collection.find_one({
            "investigation_id": investigation_id,
            "evidence_type": evidence_type,
            "source_id": source_id,
            "soft_delete": False
        })
        if duplicate:
            duplicate["_id"] = str(duplicate["_id"])
            return duplicate

        evidence_meta = {}
        timestamp = datetime.now(timezone.utc)

        def safe_object_id(val: str):
            try:
                return ObjectId(val)
            except Exception:
                return None

        if bypass_validation:
            evidence_meta = {"bypass_validation": True, "description": source_id}
        else:
            # Enforce existence and tenant boundary checks depending on type
            if evidence_type == "SECURITY_EVENT":
                sobj = safe_object_id(source_id)
                doc = await self.db["security_telemetry"].find_one({"event_id": source_id, "soft_delete": False})
                if not doc and sobj:
                    doc = await self.db["security_events"].find_one({"_id": sobj})
                if not doc:
                    raise ValueError(f"Security event {source_id} not found")
                if doc.get("organization_id") and doc["organization_id"] != org_id:
                    raise ValueError("Unauthorized: Telemetry event belongs to another tenant partition")
                evidence_meta = {"event_type": doc.get("event_type"), "severity": doc.get("severity")}
                timestamp = doc.get("timestamp") or timestamp

            elif evidence_type == "DETECTION_FINDING":
                sobj = safe_object_id(source_id)
                doc = None
                if sobj:
                    doc = await self.db["detection_findings"].find_one({"_id": sobj})
                if not doc:
                    doc = await self.db["detection_findings"].find_one({"event_id": source_id})
                if not doc:
                    raise ValueError(f"Detection finding {source_id} not found")
                if doc.get("organization_id") and doc["organization_id"] != org_id:
                    raise ValueError("Unauthorized: Finding belongs to another tenant partition")
                evidence_meta = {"detection_id": doc.get("detection_id"), "severity": doc.get("severity")}
                timestamp = doc.get("created_at") or timestamp

            elif evidence_type == "THREAT_INTELLIGENCE":
                sobj = safe_object_id(source_id)
                doc = None
                if sobj:
                    doc = await self.db["threat_indicators"].find_one({"_id": sobj})
                if not doc:
                    doc = await self.db["threat_indicators"].find_one({"value": source_id, "soft_delete": False})
                if not doc:
                    raise ValueError(f"Threat indicator {source_id} not found")
                if doc.get("organization_id") and doc["organization_id"] != org_id:
                    raise ValueError("Unauthorized: Indicator belongs to another tenant partition")
                evidence_meta = {"indicator_type": doc.get("indicator_type"), "severity": doc.get("severity"), "value": doc.get("value")}
                timestamp = doc.get("created_at") or timestamp

            elif evidence_type == "HUNT_RESULT":
                sobj = safe_object_id(source_id)
                doc = None
                if sobj:
                    doc = await self.db["hunt_findings"].find_one({"_id": sobj})
                if not doc:
                    doc = await self.db["hunt_findings"].find_one({"event_id": source_id})
                if not doc:
                    raise ValueError(f"Hunt finding {source_id} not found")
                if doc.get("organization_id") and doc["organization_id"] != org_id:
                    raise ValueError("Unauthorized: Hunt finding belongs to another tenant partition")
                evidence_meta = {"event_id": doc.get("event_id"), "severity": doc.get("severity"), "notes": doc.get("notes")}
                timestamp = doc.get("timestamp") or timestamp

            elif evidence_type == "INCIDENT":
                doc = await self.db["incidents"].find_one({"incident_id": source_id, "soft_delete": False})
                if not doc:
                    raise ValueError(f"Incident {source_id} not found")
                if doc.get("organization_id") and doc["organization_id"] != org_id:
                    raise ValueError("Unauthorized: Incident belongs to another tenant partition")
                evidence_meta = {"threat_category": doc.get("threat_category"), "severity": doc.get("threat_severity")}
                timestamp = doc.get("created_at") or timestamp

            elif evidence_type == "USER":
                doc = await self.db["users"].find_one({"email": source_id})
                if not doc:
                    sobj = safe_object_id(source_id)
                    if sobj:
                        doc = await self.db["users"].find_one({"_id": sobj})
                if not doc:
                    raise ValueError(f"User {source_id} not found")
                if doc.get("organization_id") and doc["organization_id"] != org_id:
                    raise ValueError("Unauthorized: User belongs to another organization")
                evidence_meta = {"email": doc.get("email"), "role": doc.get("role")}

            elif evidence_type == "DEVICE":
                doc = await self.db["devices"].find_one({"device_id": source_id, "soft_delete": False})
                if not doc:
                    raise ValueError(f"Device {source_id} not found")
                if doc.get("organization_id") and doc["organization_id"] != org_id:
                    raise ValueError("Unauthorized: Device belongs to another organization")
                evidence_meta = {"device_name": doc.get("device_name"), "os": doc.get("os")}

            elif evidence_type in ["IP", "DOMAIN", "URL"]:
                if len(source_id.strip()) < 3:
                    raise ValueError(f"Malformed {evidence_type} identifier: {source_id}")
                evidence_meta = {"value": source_id}

            elif evidence_type == "EMAIL_INDICATOR":
                sobj = safe_object_id(source_id)
                doc = None
                if sobj:
                    doc = await self.db["emails"].find_one({"_id": sobj})
                if not doc:
                    raise ValueError(f"Email record {source_id} not found")
                if doc.get("organization_id") and doc["organization_id"] != org_id:
                    raise ValueError("Unauthorized: Email record belongs to another tenant partition")
                evidence_meta = {"subject": doc.get("subject"), "from": doc.get("from_address")}
                timestamp = doc.get("date") or timestamp

            else:
                raise ValueError(f"Unsupported evidence type: {evidence_type}")

        evidence_doc = {
            "organization_id": org_id,
            "investigation_id": investigation_id,
            "evidence_type": evidence_type,
            "source_id": source_id,
            "timestamp": timestamp,
            "metadata": evidence_meta,
            "added_by": analyst_id,
            "soft_delete": False
        }
        res = await self.evidence_repo.create(evidence_doc)
        res["_id"] = str(res["_id"])

        # Audit
        await self.audit_repo.collection.insert_one({
            "organization_id": org_id,
            "action": "INVESTIGATION_EVIDENCE_ADDED",
            "actor": analyst_id,
            "details": {"investigation_id": investigation_id, "evidence_type": evidence_type, "source_id": source_id},
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        })
        return res

    async def remove_evidence(
        self,
        org_id: str,
        investigation_id: str,
        evidence_id: str,
        analyst_id: str
    ) -> None:
        """Remove evidence link from investigation container."""
        evidence = await self.evidence_repo.get(evidence_id)
        if not evidence or evidence.get("organization_id") != org_id or evidence.get("investigation_id") != investigation_id:
            raise ValueError("Evidence record not found")

        await self.evidence_repo.collection.update_one(
            {"_id": ObjectId(evidence_id)},
            {"$set": {"soft_delete": True}}
        )

        # Audit
        await self.audit_repo.collection.insert_one({
            "organization_id": org_id,
            "action": "INVESTIGATION_EVIDENCE_REMOVED",
            "actor": analyst_id,
            "details": {
                "investigation_id": investigation_id,
                "evidence_type": evidence.get("evidence_type"),
                "source_id": evidence.get("source_id")
            },
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        })

    async def add_note(
        self,
        org_id: str,
        investigation_id: str,
        content: str,
        analyst_id: str
    ) -> Dict[str, Any]:
        """Save analyst note tracking investigative timeline updates."""
        inv = await self.inv_repo.get(investigation_id)
        if not inv or inv.get("organization_id") != org_id:
            raise ValueError("Investigation not found")

        # Content validation
        if len(content.strip()) < 5:
            raise ValueError("Analyst note content too short (min 5 characters)")
        if len(content) > 10000:
            raise ValueError("Analyst note content exceeds maximum length (10000 characters)")

        note_doc = {
            "organization_id": org_id,
            "investigation_id": investigation_id,
            "content": content,
            "author": analyst_id,
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        }
        res = await self.note_repo.create(note_doc)
        res["_id"] = str(res["_id"])

        # Audit note creation
        await self.audit_repo.collection.insert_one({
            "organization_id": org_id,
            "action": "INVESTIGATION_NOTE_CREATED",
            "actor": analyst_id,
            "details": {"investigation_id": investigation_id, "note_id": res["_id"]},
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        })

        return res

    async def get_investigation_workspace(
        self,
        org_id: str,
        investigation_id: str
    ) -> Dict[str, Any]:
        """Fetch investigation data, dynamic timeline, entities, and relationships."""
        inv = await self.inv_repo.get(investigation_id)
        if not inv or inv.get("organization_id") != org_id:
            # Fallback for human-readable string lookup
            inv_by_id = await self.inv_repo.collection.find_one({
                "organization_id": org_id,
                "investigation_id": investigation_id,
                "soft_delete": False
            })
            if not inv_by_id:
                return {}
            inv = inv_by_id

        inv["_id"] = str(inv["_id"])
        db_inv_id = inv.get("investigation_id") or str(inv["_id"])

        # Fetch evidence references
        evidence = await self.evidence_repo.get_by_investigation(org_id, db_inv_id)
        notes = await self.note_repo.get_by_investigation(org_id, db_inv_id)
        relationships = await self.relation_repo.get_by_investigation(org_id, db_inv_id)

        # Dynamic Entity extraction (Pivoting)
        entities_map = {}
        # Harvest entities from investigation entities list (E11.1 backward-compatibility)
        for ent in inv.get("entities", []):
            ent_type = ent.get("type")
            ent_val = ent.get("value")
            if ent_type and ent_val:
                entities_map[(ent_type, ent_val)] = {
                    "type": ent_type,
                    "id": ent_val,
                    "source": "investigation_field"
                }
        for ev in evidence:
            ev_type = ev["evidence_type"]
            src_id = ev["source_id"]

            if ev_type in ["USER", "DEVICE", "IP", "DOMAIN", "URL"]:
                entities_map[(ev_type, src_id)] = {
                    "type": ev_type,
                    "id": src_id,
                    "source": "evidence"
                }
            elif ev_type == "SECURITY_EVENT":
                meta = ev.get("metadata", {})
                # Try getting details
                doc = await self.db["security_telemetry"].find_one({"event_id": src_id, "soft_delete": False})
                if doc:
                    usr = doc.get("user_id") or doc.get("payload", {}).get("user")
                    ip = doc.get("source") or doc.get("payload", {}).get("ip")
                    dom = doc.get("payload", {}).get("domain")
                    if usr: entities_map[("USER", usr)] = {"type": "USER", "id": usr, "source": "telemetry"}
                    if ip: entities_map[("IP", ip)] = {"type": "IP", "id": ip, "source": "telemetry"}
                    if dom: entities_map[("DOMAIN", dom)] = {"type": "DOMAIN", "id": dom, "source": "telemetry"}

        # Dynamic Timeline generation
        timeline = []
        for ev in evidence:
            timeline.append({
                "timestamp": ev.get("timestamp") or datetime.now(timezone.utc),
                "type": "EVIDENCE_ADDED",
                "title": f"Evidence Linked: {ev['evidence_type']}",
                "description": f"Analyst linked {ev['evidence_type']} source id: {ev['source_id']}",
                "actor": ev.get("added_by") or "SYSTEM"
            })
        for n in notes:
            timeline.append({
                "timestamp": n.get("timestamp") or datetime.now(timezone.utc),
                "type": "ANALYST_NOTE",
                "title": "Analyst Investigation Note",
                "description": n["content"],
                "actor": n.get("author") or "SYSTEM"
            })
        for rel in relationships:
            timeline.append({
                "timestamp": rel.get("timestamp") or datetime.now(timezone.utc),
                "type": "RELATIONSHIP_IDENTIFIED",
                "title": "Relationship Discovered",
                "description": f"Linked {rel['source_type']} ({rel['source_id']}) to {rel['target_type']} ({rel['target_id']}) via {rel['relationship_type']}",
                "actor": "Correlation Engine"
            })

        # Sort timeline chronologically
        timeline.sort(key=lambda item: item["timestamp"])

        return {
            "investigation": inv,
            "evidence": evidence,
            "entities": list(entities_map.values()),
            "relationships": relationships,
            "notes": notes,
            "timeline": timeline
        }

    async def correlate_investigation(
        self,
        org_id: str,
        investigation_id: str
    ) -> Dict[str, Any]:
        """deterministic multi-signal correlation engine."""
        inv = await self.inv_repo.get(investigation_id)
        if not inv or inv.get("organization_id") != org_id:
            raise ValueError("Investigation not found")

        # 1. Fetch current evidence
        evidence = await self.evidence_repo.get_by_investigation(org_id, investigation_id)

        # Enforce resource limits: abort if too many entities/evidence
        if len(evidence) > 100:
            raise ValueError("Resource limits exceeded: Too many evidence elements to correlate.")

        # Log correlation start audit
        await self.audit_repo.collection.insert_one({
            "organization_id": org_id,
            "action": "INVESTIGATION_CORRELATION_STARTED",
            "actor": "SYSTEM",
            "details": {"investigation_id": investigation_id},
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        })

        # 2. Extract Seed Entities from evidence
        seed_users = set()
        seed_ips = set()
        seed_domains = set()
        seed_devices = set()

        for ev in evidence:
            ev_type = ev["evidence_type"]
            src_id = ev["source_id"]

            if ev_type == "USER":
                seed_users.add(src_id)
            elif ev_type == "IP":
                seed_ips.add(src_id)
            elif ev_type == "DOMAIN":
                seed_domains.add(src_id)
            elif ev_type == "DEVICE":
                seed_devices.add(src_id)
            elif ev_type == "SECURITY_EVENT":
                doc = await self.db["security_telemetry"].find_one({"event_id": src_id, "soft_delete": False})
                if doc:
                    usr = doc.get("user_id") or doc.get("payload", {}).get("user")
                    ip = doc.get("source") or doc.get("payload", {}).get("ip")
                    dom = doc.get("payload", {}).get("domain")
                    if usr: seed_users.add(usr)
                    if ip: seed_ips.add(ip)
                    if dom: seed_domains.add(dom)

        # Enforce max seed limit (Max 20 seed entities to prevent graph explosion)
        seed_users = list(seed_users)[:20]
        seed_ips = list(seed_ips)[:20]
        seed_domains = list(seed_domains)[:20]
        seed_devices = list(seed_devices)[:20]

        generated_relationships = []

        # 3. Correlation signals

        # Fetch recent telemetry events in-memory to resolve mock query nesting limitations
        telemetry_cursor = self.db["security_telemetry"].find({
            "organization_id": org_id,
            "soft_delete": False
        }).sort("timestamp", -1)
        telemetry_events = await telemetry_cursor.to_list(length=100)

        # Signal 1 & 2: Connected users and IPs from login/syslog events
        for user in seed_users:
            if user == "unknown": continue
            
            # In-memory filter for user matches
            matching_events = [
                evt for evt in telemetry_events
                if evt.get("user_id") == user or evt.get("payload", {}).get("user") == user
            ]

            for evt in matching_events:
                evt_id = evt["event_id"]
                src_ip = evt.get("source") or evt.get("payload", {}).get("ip")
                device = evt.get("payload", {}).get("device_id")

                if src_ip:
                    generated_relationships.append({
                        "source_type": "USER",
                        "source_id": user,
                        "target_type": "IP",
                        "target_id": src_ip,
                        "relationship_type": "USER_CONNECTED_TO_IP",
                        "confidence": "HIGH",
                        "explanation": f"Observed login action from IP {src_ip} in E10 telemetry",
                        "evidence_reference": evt_id
                    })
                if device:
                    generated_relationships.append({
                        "source_type": "USER",
                        "source_id": user,
                        "target_type": "DEVICE",
                        "target_id": device,
                        "relationship_type": "USER_USED_DEVICE",
                        "confidence": "HIGH",
                        "explanation": f"Observed login action from device ID {device} in E10 telemetry",
                        "evidence_reference": evt_id
                    })

        # Signal 3: E4 Threat intelligence indicator overlaps
        for ip in seed_ips:
            # Query E4 indicators
            ioc = await self.db["threat_indicators"].find_one({
                "organization_id": org_id,
                "value": ip,
                "soft_delete": False
            })
            if ioc:
                # In-memory filter for IP matches
                matches = [
                    evt for evt in telemetry_events
                    if evt.get("source") == ip or evt.get("payload", {}).get("ip") == ip
                ]
                for m in matches[:20]:
                    generated_relationships.append({
                        "source_type": "IP",
                        "source_id": ip,
                        "target_type": "EVENT",
                        "target_id": m["event_id"],
                        "relationship_type": "IOC_MATCHED_EVENT",
                        "confidence": "HIGH",
                        "explanation": f"IP matching known indicator '{ioc.get('description')}' observed in event logs",
                        "evidence_reference": m["event_id"]
                    })

        for dom in seed_domains:
            # Query E4 indicators
            ioc = await self.db["threat_indicators"].find_one({
                "organization_id": org_id,
                "value": dom,
                "soft_delete": False
            })
            if ioc:
                # In-memory filter for Domain matches
                matches = [
                    evt for evt in telemetry_events
                    if evt.get("payload", {}).get("domain") == dom
                ]
                for m in matches[:20]:
                    generated_relationships.append({
                        "source_type": "DOMAIN",
                        "source_id": dom,
                        "target_type": "EVENT",
                        "target_id": m["event_id"],
                        "relationship_type": "IOC_MATCHED_EVENT",
                        "confidence": "HIGH",
                        "explanation": f"Domain matching known indicator '{ioc.get('description')}' observed in event logs",
                        "evidence_reference": m["event_id"]
                    })

        # Signal 4: E9 UEBA user risk score anomaly flags
        for user in seed_users:
            if user == "unknown": continue
            # Query ml features anomalies
            feat = await self.db["ml_features"].find_one({
                "organization_id": org_id,
                "entity_id": user,
                "feature_name": "user_risk_score",
                "soft_delete": False
            })
            if feat and feat.get("value", 0.0) >= 0.50:
                generated_relationships.append({
                    "source_type": "USER",
                    "source_id": user,
                    "target_type": "USER",
                    "target_id": user,
                    "relationship_type": "UEBA_FLAGGED_USER",
                    "confidence": "HIGH",
                    "explanation": f"UEBA anomaly risk score is elevated: {int(feat['value'] * 100)}/100",
                    "evidence_reference": str(feat["_id"])
                })

        # Signal 5: E11.3 Active Detection Findings
        # Find active findings matching seed events
        for ev in evidence:
            if ev["evidence_type"] == "SECURITY_EVENT":
                evt_id = ev["source_id"]
                finding = await self.db["detection_findings"].find_one({
                    "organization_id": org_id,
                    "event_id": evt_id,
                    "soft_delete": False
                })
                if finding:
                    generated_relationships.append({
                        "source_type": "DETECTION",
                        "source_id": finding.get("detection_id") or "UNKNOWN",
                        "target_type": "EVENT",
                        "target_id": evt_id,
                        "relationship_type": "DETECTION_MATCHED_EVENT",
                        "confidence": "HIGH",
                        "explanation": f"Production detection matched telemetry event. Finding ID: {str(finding['_id'])}",
                        "evidence_reference": evt_id
                    })

        # 4. Limit generated relationships list to prevent graph explosion (Max 50)
        final_rels = generated_relationships[:50]

        # 5. Persist Relationships checking duplicates
        inserted = 0
        for rel in final_rels:
            # Check duplicate link
            dup = await self.relation_repo.collection.find_one({
                "investigation_id": investigation_id,
                "source_id": rel["source_id"],
                "target_id": rel["target_id"],
                "relationship_type": rel["relationship_type"],
                "soft_delete": False
            })
            if not dup:
                rel["organization_id"] = org_id
                rel["investigation_id"] = investigation_id
                rel["timestamp"] = datetime.now(timezone.utc)
                rel["soft_delete"] = False
                await self.relation_repo.create(rel)
                inserted += 1

        # Log completion audit
        await self.audit_repo.collection.insert_one({
            "organization_id": org_id,
            "action": "INVESTIGATION_CORRELATION_COMPLETED",
            "actor": "SYSTEM",
            "details": {"investigation_id": investigation_id, "relationships_created": inserted},
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        })

        return {"status": "SUCCESS", "relationships_created": inserted}

investigation_service = InvestigationService()
