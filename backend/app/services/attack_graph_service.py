import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set
from bson import ObjectId

from app.database.connection import db_manager
from app.services.investigation_service import investigation_service

logger = logging.getLogger(__name__)

# Colors for UI visualization compatibility
TYPE_COLORS = {
    "INVESTIGATION": "#ef4444",
    "INCIDENT": "#f87171",
    "USER": "#38bdf8",
    "DEVICE": "#fb7185",
    "IP": "#fbbf24",
    "DOMAIN": "#34d399",
    "URL": "#a78bfa",
    "EMAIL": "#818cf8",
    "DETECTION": "#f43f5e",
    "FINDING": "#ec4899",
    "CAMPAIGN": "#c084fc",
    "EVENT": "#64748b"
}

class AttackGraphService:
    @property
    def db(self):
        return db_manager.db

    async def build_graph_for_investigation(
        self,
        org_id: str,
        investigation_id: str,
        max_depth: int = 2
    ) -> Dict[str, Any]:
        """Construct interactive evidence-grounded attack graph traversing entity references."""
        # 1. Fetch E11.5 workspace context
        workspace = await investigation_service.get_investigation_workspace(org_id, investigation_id)
        if not workspace:
            # Try to lookup by investigation_id field instead of _id (E11.1 E2E compatibility)
            inv_by_id = await self.db["investigations"].find_one({
                "organization_id": org_id,
                "investigation_id": investigation_id,
                "soft_delete": False
            })
            if inv_by_id:
                workspace = await investigation_service.get_investigation_workspace(org_id, str(inv_by_id["_id"]))
            else:
                raise ValueError("Investigation case not found")

        inv = workspace["investigation"]
        evidence = workspace["evidence"]
        entities = workspace["entities"]
        relationships = workspace["relationships"]
        notes = workspace["notes"]

        # Traversal limits configuration
        max_nodes = 250
        max_edges = 500
        depth_limit = min(max_depth, 3)

        visited_nodes: Set[str] = set()
        visited_edges: Set[str] = set()

        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        def add_node(node_id: str, label: str, type_val: str, metadata: Dict[str, Any] = None):
            if node_id in visited_nodes:
                return
            if len(nodes) >= max_nodes:
                return
            visited_nodes.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "type": type_val,
                "color": TYPE_COLORS.get(type_val, "#94a3b8"),
                "metadata": metadata or {}
            })

        def add_edge(source: str, target: str, rel_type: str, label: str, confidence: str = "MEDIUM", evidence_refs: List[str] = None, explanation: str = ""):
            edge_key = f"{source}->{target}->{rel_type}"
            if edge_key in visited_edges:
                return
            if len(edges) >= max_edges:
                return
            visited_edges.add(edge_key)
            edges.append({
                "source": source,
                "target": target,
                "type": rel_type,
                "label": label,
                "confidence": confidence,
                "evidence_refs": evidence_refs or [],
                "explanation": explanation
            })

        # Ground Node: The investigation itself
        inv_node_id = f"INV-{inv.get('investigation_id') or inv['_id']}"
        add_node(inv_node_id, inv.get("title"), "INVESTIGATION", {
            "status": inv.get("status"),
            "severity": inv.get("severity"),
            "priority": inv.get("priority"),
            "created_by": inv.get("created_by")
        })

        # Map entities and enrich them
        for ent in entities:
            ent_type = ent["type"]
            ent_id = ent["id"]
            node_id = f"{ent_type}-{ent_id}"

            # Fetch enriches
            meta = {"source": ent.get("source", "evidence")}
            if ent_type in ["IP", "DOMAIN", "URL"]:
                ioc = await self.db["threat_indicators"].find_one({
                    "organization_id": org_id,
                    "value": ent_id,
                    "soft_delete": False
                })
                if ioc:
                    meta["threat_intel_reputation"] = ioc.get("severity", "MEDIUM")
                    meta["threat_intel_description"] = ioc.get("description")
                    meta["threat_intel_class"] = ioc.get("indicator_type")

            elif ent_type == "USER":
                feat = await self.db["ml_features"].find_one({
                    "organization_id": org_id,
                    "entity_id": ent_id,
                    "feature_name": "user_risk_score",
                    "soft_delete": False
                })
                if feat:
                    meta["ueba_risk_score"] = feat.get("value")

            add_node(node_id, ent_id, ent_type, meta)
            # Edge from Investigation to entity
            add_edge(inv_node_id, node_id, "HAS_EVIDENCE", "Linked Evidence", "HIGH", [], f"Analyzed indicator '{ent_id}'")

        # Map generated relationships (E11.5)
        for rel in relationships:
            src_node = f"{rel['source_type']}-{rel['source_id']}"
            tgt_node = f"{rel['target_type']}-{rel['target_id']}"
            
            # Ensure nodes exist
            add_node(src_node, rel['source_id'], rel['source_type'])
            add_node(tgt_node, rel['target_id'], rel['target_type'])
            
            add_edge(
                source=src_node,
                target=tgt_node,
                rel_type=rel['relationship_type'],
                label=rel['relationship_type'].replace("_", " "),
                confidence=rel.get('confidence', 'MEDIUM'),
                evidence_refs=[rel.get('evidence_reference')] if rel.get('evidence_reference') else [],
                explanation=rel.get('explanation', '')
            )

        # 2. Bounded Traversal Expansion (Depth traversal)
        if depth_limit > 1:
            # We can expand from our seed entities to find other related investigations/incidents
            seed_entities = list(entities)
            
            # Find investigations sharing the same entities
            for ent in seed_entities:
                ent_type = ent["type"]
                ent_id = ent["id"]
                node_id = f"{ent_type}-{ent_id}"

                # Query other evidence links sharing this entity key
                cursor = self.db["investigation_evidence"].find({
                    "organization_id": org_id,
                    "evidence_type": ent_type,
                    "source_id": ent_id,
                    "investigation_id": {"$ne": inv.get("investigation_id")},
                    "soft_delete": False
                })
                shared_evidence = await cursor.to_list(length=10)

                for ev in shared_evidence:
                    other_inv_id = ev["investigation_id"]
                    other_node_id = f"INV-{other_inv_id}"

                    # Fetch other investigation details
                    other_inv = await self.db["investigations"].find_one({
                        "organization_id": org_id,
                        "investigation_id": other_inv_id,
                        "soft_delete": False
                    })
                    if other_inv:
                        add_node(other_node_id, other_inv.get("title"), "INVESTIGATION", {
                            "status": other_inv.get("status"),
                            "severity": other_inv.get("severity"),
                            "priority": other_inv.get("priority")
                        })
                        add_edge(
                            source=other_node_id,
                            target=node_id,
                            rel_type="SHARED_INDICATOR",
                            label="Shared Indicator",
                            confidence="HIGH",
                            evidence_refs=[str(ev["_id"])],
                            explanation=f"Investigation shares indicator '{ent_id}'"
                        )

        # Enforce MITRE technique enriches for detections/findings
        # Retrieve rule technique mapping from active rules
        rules_cursor = self.db["detection_rules"].find({"organization_id": org_id, "is_active": True})
        rules = await rules_cursor.to_list(length=100)
        rules_map = {r["rule_id"]: r for r in rules}

        for node in nodes:
            if node["type"] == "DETECTION" or node["type"] == "FINDING":
                det_id = node["metadata"].get("detection_id") or node["id"].split("-")[-1]
                rule = rules_map.get(det_id)
                if rule and "mitre_technique" in rule:
                    node["metadata"]["mitre_technique"] = rule["mitre_technique"]
                    node["metadata"]["mitre_description"] = rule.get("mitre_description", "")

        # Add campaign overlay (E11.1 backward-compatibility)
        campaigns_cursor = self.db["campaigns"].find({
            "organization_id": org_id,
            "soft_delete": False
        })
        org_campaigns = await campaigns_cursor.to_list(length=100)
        node_keys = {n["label"] for n in nodes}
        for camp in org_campaigns:
            camp_indicators = camp.get("indicators", [])
            if any(ind in node_keys for ind in camp_indicators):
                camp_node_id = f"CAMP-{camp.get('campaign_id') or str(camp['_id'])}"
                add_node(camp_node_id, camp.get("name"), "CAMPAIGN", {
                    "status": camp.get("status"),
                    "confidence": camp.get("confidence")
                })
                # Link campaign to overlapping indicators
                for ind in camp_indicators:
                    if ind in node_keys:
                        matched_node = next((n for n in nodes if n["label"] == ind), None)
                        if matched_node:
                            add_edge(
                                source=camp_node_id,
                                target=matched_node["id"],
                                rel_type="CAMPAIGN_ATTRIBUTION",
                                label="Attributed Campaign",
                                confidence="HIGH",
                                evidence_refs=[],
                                explanation=f"Indicator '{ind}' belongs to Campaign '{camp.get('name')}'"
                            )

        return {
            "nodes": nodes,
            "edges": edges
        }

attack_graph_service = AttackGraphService()
