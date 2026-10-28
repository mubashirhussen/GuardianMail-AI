import logging
from typing import Dict, Any, List, Optional
from app.database.connection import db_manager

logger = logging.getLogger("guardianmail.response_playbook_service")

class PlaybookResolver:
    async def resolve_playbook(self, organization_id: str, action_type: str) -> Optional[Dict[str, Any]]:
        """Query E6 soar_playbooks collection for active, tenant-scoped playbooks with fallback defaults."""
        db = db_manager.db
        
        # Check active playbook in DB first
        query = {
            "organization_id": organization_id,
            "action_type": action_type,
            "status": "ENABLED",
            "soft_delete": {"$ne": True}
        }
        playbook = await db["soar_playbooks"].find_one(query)
        if playbook:
            return {
                "playbook_id": playbook.get("playbook_id"),
                "playbook_name": playbook.get("playbook_name"),
                "action_type": playbook.get("action_type"),
                "version": playbook.get("version", "1.0")
            }

        # Fallback to default tenant-scoped mock registry if collection is empty
        fallbacks = {
            "QUARANTINE_EMAIL": {
                "playbook_id": "PLAYBOOK-EMAIL-QUARANTINE",
                "playbook_name": "Phishing Email Automatic Quarantine Playbook",
                "action_type": "QUARANTINE_EMAIL",
                "version": "1.0"
            },
            "ISOLATE_HOST": {
                "playbook_id": "PLAYBOOK-HOST-ISOLATION",
                "playbook_name": "Compromised Host Device Isolation Playbook",
                "action_type": "ISOLATE_HOST",
                "version": "1.0"
            },
            "RESET_CREDENTIAL": {
                "playbook_id": "PLAYBOOK-CREDENTIAL-RESET",
                "playbook_name": "Privileged User Account Password Reset Playbook",
                "action_type": "RESET_CREDENTIAL",
                "version": "1.0"
            },
            "BLOCK_INDICATOR": {
                "playbook_id": "PLAYBOOK-BLOCK-INDICATOR",
                "playbook_name": "Threat IOC IP/Domain Firewall Block Playbook",
                "action_type": "BLOCK_INDICATOR",
                "version": "1.0"
            },
            "EXPORT_GRC_EVIDENCE": {
                "playbook_id": "PLAYBOOK-GRC-EXPORT",
                "playbook_name": "GRC Evidence Timelines Automated Export Playbook",
                "action_type": "EXPORT_GRC_EVIDENCE",
                "version": "1.0"
            }
        }

        return fallbacks.get(action_type)

class EvidenceEvaluator:
    @staticmethod
    def evaluate_evidence_sufficiency(action_type: str, evidence_refs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Verify that a candidate action possesses sufficient evidence context to execute safely (E11.8.3)."""
        present_types = {ref.get("source_type") for ref in evidence_refs}
        
        requirements = {
            "ISOLATE_HOST": ["FINDING"],
            "QUARANTINE_EMAIL": ["FINDING"],
            "BLOCK_INDICATOR": ["IOC"],
            "RESET_CREDENTIAL": ["UEBA_SIGNAL"]
        }

        # If action is low-risk, no strict evidence is required
        required_types = requirements.get(action_type)
        if not required_types:
            return {
                "sufficient": True,
                "required_types": [],
                "missing_types": []
            }

        # If evidence list is entirely empty, reject
        if not evidence_refs:
            return {
                "sufficient": False,
                "required_types": required_types,
                "missing_types": required_types
            }

        missing_types = [t for t in required_types if t not in present_types]
        
        # If we require IOC, but we only have a FINDING, check if finding mentions IOC or handle fallback
        # Special check: allow CAMPAIGN to satisfy FINDING requirement
        if "FINDING" in required_types and "CAMPAIGN" in present_types:
            if "FINDING" in missing_types:
                missing_types.remove("FINDING")

        # Special check: allow FINDING to satisfy IOC requirement
        if "IOC" in required_types and "FINDING" in present_types:
            if "IOC" in missing_types:
                missing_types.remove("IOC")

        # Special check: allow FINDING to satisfy UEBA requirement
        if "UEBA_SIGNAL" in required_types and "FINDING" in present_types:
            if "UEBA_SIGNAL" in missing_types:
                missing_types.remove("UEBA_SIGNAL")

        return {
            "sufficient": len(missing_types) == 0,
            "required_types": required_types,
            "missing_types": missing_types
        }

playbook_resolver = PlaybookResolver()
evidence_evaluator = EvidenceEvaluator()
