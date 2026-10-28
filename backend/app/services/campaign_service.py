import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from bson import ObjectId

from app.database.connection import db_manager
from app.repositories.detection_repo import CampaignRepository
from app.repositories.audit_repo import AuditRepository

logger = logging.getLogger(__name__)

VALID_CAMPAIGN_STATUSES = ["SUSPECTED", "UNDER_REVIEW", "CONFIRMED", "DISMISSED", "CLOSED"]
VALID_CONFIDENCES = ["low", "medium", "high", "confirmed"]

class CampaignService:
    @property
    def db(self):
        return db_manager.db

    @property
    def campaign_repo(self):
        return CampaignRepository(self.db)

    @property
    def audit_repo(self):
        return AuditRepository(self.db)

    async def create_campaign(
        self,
        org_id: str,
        name: str,
        description: str,
        status: str,
        confidence: str,
        analyst_id: str
    ) -> Dict[str, Any]:
        """Manually initiate a suspected threat campaign case container."""
        if status not in VALID_CAMPAIGN_STATUSES:
            raise ValueError(f"Invalid campaign status: {status}")
        if confidence not in VALID_CONFIDENCES:
            raise ValueError(f"Invalid confidence level: {confidence}")

        doc = {
            "organization_id": org_id,
            "campaign_id": f"CAMP-{uuid.uuid4().hex[:6].upper()}",
            "name": name,
            "description": description,
            "status": status,
            "confidence": confidence,
            "indicators": [],
            "affected_users": [],
            "related_incidents": [],
            "related_investigations": [],
            "notes": [],
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "soft_delete": False
        }
        res = await self.campaign_repo.create(doc)
        doc["_id"] = str(res["_id"])

        # Audit
        await self.audit_repo.collection.insert_one({
            "organization_id": org_id,
            "action": "CAMPAIGN_CREATED",
            "actor": analyst_id,
            "details": {"campaign_id": doc["campaign_id"], "name": name},
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        })
        return doc

    async def get_campaign_workspace(self, org_id: str, campaign_id: str) -> Dict[str, Any]:
        """Retrieve campaign case details, linked investigations, and chronological timeline."""
        # Find campaign
        camp = await self.db["campaigns"].find_one({
            "organization_id": org_id,
            "$or": [{"campaign_id": campaign_id}, {"_id": ObjectId(campaign_id) if len(campaign_id) == 24 else None}],
            "soft_delete": False
        })
        if not camp:
            return {}

        camp["_id"] = str(camp["_id"])

        # Fetch related investigations details
        linked_invs = []
        timeline = []

        investigation_ids = camp.get("related_investigations", [])
        # Fallback to related_incidents list if present
        for i_id in camp.get("related_incidents", []):
            if i_id not in investigation_ids:
                investigation_ids.append(i_id)

        for inv_id in investigation_ids:
            inv = await self.db["investigations"].find_one({
                "organization_id": org_id,
                "$or": [{"investigation_id": inv_id}, {"_id": ObjectId(inv_id) if len(inv_id) == 24 else None}],
                "soft_delete": False
            })
            if inv:
                inv["_id"] = str(inv["_id"])
                linked_invs.append(inv)
                
                # Fetch evidence for timeline
                cursor = self.db["investigation_evidence"].find({
                    "organization_id": org_id,
                    "investigation_id": inv["investigation_id"],
                    "soft_delete": False
                })
                evidence_items = await cursor.to_list(length=50)

                for ev in evidence_items:
                    timeline.append({
                        "timestamp": ev["timestamp"],
                        "type": "CAMPAIGN_EVIDENCE",
                        "title": f"Incident {inv['investigation_id']} - Linked {ev['evidence_type']}",
                        "description": f"Observed indicator '{ev['source_id']}' associated with incident '{inv['title']}'",
                        "source": f"Investigation {inv_id}"
                    })

        # Append campaign notes to timeline
        for note in camp.get("notes", []):
            timeline.append({
                "timestamp": note["timestamp"],
                "type": "CAMPAIGN_NOTE",
                "title": "Analyst Campaign Note",
                "description": note["content"],
                "source": note["author"]
            })

        # Sort timeline chronologically
        timeline.sort(key=lambda item: item["timestamp"])

        return {
            "campaign": camp,
            "investigations": linked_invs,
            "timeline": timeline
        }

    async def update_campaign(
        self,
        org_id: str,
        campaign_id: str,
        update_data: Dict[str, Any],
        analyst_id: str
    ) -> Dict[str, Any]:
        """Update campaign metadata and lifecycle status."""
        camp = await self.db["campaigns"].find_one({
            "organization_id": org_id,
            "$or": [{"campaign_id": campaign_id}, {"_id": ObjectId(campaign_id) if len(campaign_id) == 24 else None}],
            "soft_delete": False
        })
        if not camp:
            raise ValueError("Campaign not found")

        current_status = camp.get("status", "SUSPECTED")
        new_status = update_data.get("status")

        # Validate status transitions
        if new_status and new_status != current_status:
            if new_status not in VALID_CAMPAIGN_STATUSES:
                raise ValueError("Invalid campaign status value")

            # Audit status transition
            await self.audit_repo.collection.insert_one({
                "organization_id": org_id,
                "action": "CAMPAIGN_STATUS_CHANGED",
                "actor": analyst_id,
                "details": {
                    "campaign_id": camp["campaign_id"],
                    "old_status": current_status,
                    "new_status": new_status
                },
                "timestamp": datetime.now(timezone.utc),
                "soft_delete": False
            })

        if "confidence" in update_data and update_data["confidence"] not in VALID_CONFIDENCES:
            raise ValueError("Invalid confidence level")

        update_data["updated_at"] = datetime.now(timezone.utc)

        await self.db["campaigns"].update_one(
            {"_id": camp["_id"]},
            {"$set": update_data}
        )

        # Audit update
        await self.audit_repo.collection.insert_one({
            "organization_id": org_id,
            "action": "CAMPAIGN_UPDATED",
            "actor": analyst_id,
            "details": {"campaign_id": camp["campaign_id"], "fields": list(update_data.keys())},
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        })

        updated = await self.db["campaigns"].find_one({"_id": camp["_id"]})
        updated["_id"] = str(updated["_id"])
        return updated

    async def add_evidence_pointer(
        self,
        org_id: str,
        campaign_id: str,
        evidence_type: str,
        source_id: str,
        analyst_id: str
    ) -> Dict[str, Any]:
        """Link referenced investigation or indicator to campaign case container."""
        camp = await self.db["campaigns"].find_one({
            "organization_id": org_id,
            "$or": [{"campaign_id": campaign_id}, {"_id": ObjectId(campaign_id) if len(campaign_id) == 24 else None}],
            "soft_delete": False
        })
        if not camp:
            raise ValueError("Campaign not found")

        update_field = ""
        if evidence_type == "INVESTIGATION":
            # Verify investigation exists
            inv = await self.db["investigations"].find_one({
                "organization_id": org_id,
                "$or": [{"investigation_id": source_id}, {"_id": ObjectId(source_id) if len(source_id) == 24 else None}],
                "soft_delete": False
            })
            if not inv:
                raise ValueError(f"Investigation {source_id} not found")
            update_field = "related_investigations"
            source_id = inv.get("investigation_id") or str(inv["_id"])

        elif evidence_type in ["IP", "DOMAIN", "URL", "FILE_HASH"]:
            update_field = "indicators"

        elif evidence_type == "USER":
            update_field = "affected_users"

        else:
            raise ValueError(f"Unsupported campaign evidence type: {evidence_type}")

        # Update array checking duplicates
        current_list = camp.get(update_field, [])
        if source_id not in current_list:
            current_list.append(source_id)
            await self.db["campaigns"].update_one(
                {"_id": camp["_id"]},
                {"$set": {update_field: current_list, "updated_at": datetime.now(timezone.utc)}}
            )
            # Log audit
            await self.audit_repo.collection.insert_one({
                "organization_id": org_id,
                "action": "CAMPAIGN_EVIDENCE_ADDED",
                "actor": analyst_id,
                "details": {"campaign_id": camp["campaign_id"], "type": evidence_type, "value": source_id},
                "timestamp": datetime.now(timezone.utc),
                "soft_delete": False
            })

        updated = await self.db["campaigns"].find_one({"_id": camp["_id"]})
        updated["_id"] = str(updated["_id"])
        return updated

    async def remove_evidence_pointer(
        self,
        org_id: str,
        campaign_id: str,
        evidence_type: str,
        source_id: str,
        analyst_id: str
    ) -> Dict[str, Any]:
        """Unlink evidence pointer from campaign workspace."""
        camp = await self.db["campaigns"].find_one({
            "organization_id": org_id,
            "$or": [{"campaign_id": campaign_id}, {"_id": ObjectId(campaign_id) if len(campaign_id) == 24 else None}],
            "soft_delete": False
        })
        if not camp:
            raise ValueError("Campaign not found")

        update_field = ""
        if evidence_type == "INVESTIGATION":
            update_field = "related_investigations"
        elif evidence_type in ["IP", "DOMAIN", "URL", "FILE_HASH"]:
            update_field = "indicators"
        elif evidence_type == "USER":
            update_field = "affected_users"
        else:
            raise ValueError("Invalid campaign evidence type")

        current_list = camp.get(update_field, [])
        if source_id in current_list:
            current_list.remove(source_id)
            await self.db["campaigns"].update_one(
                {"_id": camp["_id"]},
                {"$set": {update_field: current_list, "updated_at": datetime.now(timezone.utc)}}
            )
            # Log audit
            await self.audit_repo.collection.insert_one({
                "organization_id": org_id,
                "action": "CAMPAIGN_EVIDENCE_REMOVED",
                "actor": analyst_id,
                "details": {"campaign_id": camp["campaign_id"], "type": evidence_type, "value": source_id},
                "timestamp": datetime.now(timezone.utc),
                "soft_delete": False
            })

        updated = await self.db["campaigns"].find_one({"_id": camp["_id"]})
        updated["_id"] = str(updated["_id"])
        return updated

    async def add_note(
        self,
        org_id: str,
        campaign_id: str,
        content: str,
        author_id: str
    ) -> Dict[str, Any]:
        """Append notes logged by analysts reviewing threat campaign models."""
        camp = await self.db["campaigns"].find_one({
            "organization_id": org_id,
            "$or": [{"campaign_id": campaign_id}, {"_id": ObjectId(campaign_id) if len(campaign_id) == 24 else None}],
            "soft_delete": False
        })
        if not camp:
            raise ValueError("Campaign not found")

        note = {
            "content": content,
            "author": author_id,
            "timestamp": datetime.now(timezone.utc)
        }

        notes = camp.get("notes", [])
        notes.append(note)

        await self.db["campaigns"].update_one(
            {"_id": camp["_id"]},
            {"$set": {"notes": notes, "updated_at": datetime.now(timezone.utc)}}
        )

        # Audit
        await self.audit_repo.collection.insert_one({
            "organization_id": org_id,
            "action": "CAMPAIGN_REVIEWED",
            "actor": author_id,
            "details": {"campaign_id": camp["campaign_id"], "note": content[:50]},
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        })

        updated = await self.db["campaigns"].find_one({"_id": camp["_id"]})
        updated["_id"] = str(updated["_id"])
        return updated

    async def run_campaign_correlation_scan(self, org_id: str) -> Dict[str, Any]:
        """Scan active investigations for shared indicators and generate candidate campaigns."""
        # 1. Fetch active investigations
        cursor = self.db["investigations"].find({
            "organization_id": org_id,
            "status": {"$ne": "CLOSED"},
            "soft_delete": False
        })
        investigations = await cursor.to_list(length=100)

        if len(investigations) < 2:
            return {"status": "SUCCESS", "campaigns_discovered": 0}

        # Enforce limits (max 50 investigations to cross-reference)
        investigations = investigations[:50]

        # Extract details for each investigation
        inv_data = []
        for inv in investigations:
            inv_id = inv.get("investigation_id") or str(inv["_id"])
            
            # Fetch evidence indicators
            ev_cursor = self.db["investigation_evidence"].find({
                "organization_id": org_id,
                "investigation_id": inv_id,
                "soft_delete": False
            })
            evidence = await ev_cursor.to_list(length=50)
            
            indicators = [ev["source_id"] for ev in evidence if ev["evidence_type"] in ["IP", "DOMAIN", "URL", "FILE_HASH"]]
            users = [ev["source_id"] for ev in evidence if ev["evidence_type"] == "USER"]
            devices = [ev["source_id"] for ev in evidence if ev["evidence_type"] == "DEVICE"]
            
            inv_data.append({
                "id": inv_id,
                "title": inv["title"],
                "indicators": set(indicators),
                "users": set(users),
                "devices": set(devices),
                "created_at": inv.get("created_at") or datetime.now(timezone.utc)
            })

        discovered = 0

        # Compare pairs
        for i in range(len(inv_data)):
            for j in range(i + 1, len(inv_data)):
                inv_a = inv_data[i]
                inv_b = inv_data[j]

                # Compute overlapping details
                shared_iocs = inv_a["indicators"].intersection(inv_b["indicators"])
                shared_users = inv_a["users"].intersection(inv_b["users"])
                shared_devices = inv_a["devices"].intersection(inv_b["devices"])

                score = 0
                factors = []

                if shared_iocs:
                    score += 40 * len(shared_iocs)
                    factors.append(f"Shared IOCs: {list(shared_iocs)}")

                if shared_users:
                    score += 15 * len(shared_users)
                    factors.append(f"Shared Users: {list(shared_users)}")

                if shared_devices:
                    score += 15 * len(shared_devices)
                    factors.append(f"Shared Devices: {list(shared_devices)}")

                # Check temporal proximity (7-day window)
                time_delta = abs((inv_a["created_at"] - inv_b["created_at"]).total_seconds())
                if time_delta <= 86400 * 7:
                    score += 10
                    factors.append("Temporal proximity (created within 7 days)")

                # If threshold (30 points) exceeded, create suspected campaign candidate
                if score >= 30:
                    cand_ioc = list(shared_iocs)[0] if shared_iocs else "Shared Assets"
                    camp_name = f"Suspected Campaign: Overlap on {cand_ioc}"
                    camp_desc = f"Candidate discovered via multi-incident scan. Contributing factors: {'; '.join(factors)}"
                    
                    # Check if matching campaign already registered
                    existing = await self.db["campaigns"].find_one({
                        "organization_id": org_id,
                        "name": camp_name,
                        "soft_delete": False
                    })
                    if not existing:
                        await self.create_campaign(
                            org_id=org_id,
                            name=camp_name,
                            description=camp_desc,
                            status="SUSPECTED",
                            confidence="low" if score < 60 else "medium",
                            analyst_id="SYSTEM"
                        )
                        
                        # Fetch the newly created campaign to link the investigations
                        new_camp = await self.db["campaigns"].find_one({
                            "organization_id": org_id,
                            "name": camp_name,
                            "soft_delete": False
                        })
                        if new_camp:
                            await self.db["campaigns"].update_one(
                                {"_id": new_camp["_id"]},
                                {"$set": {
                                    "related_investigations": [inv_a["id"], inv_b["id"]],
                                    "indicators": list(shared_iocs)
                                }}
                            )
                        discovered += 1

        return {"status": "SUCCESS", "campaigns_discovered": discovered}

campaign_service = CampaignService()
