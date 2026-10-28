from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import Field
from app.models.base import BaseMongoModel

class GraphNode(BaseMongoModel):
    """Pydantic representation of an Attack Graph Entity Node."""
    node_id: str = Field(..., description="Unique node identifier, e.g. USER-admin")
    organization_id: str
    entity_type: str = Field(..., description="USER, DEVICE, IP, DOMAIN, URL, EMAIL, FILE_HASH, EVENT, DETECTION, FINDING, INCIDENT, INVESTIGATION, IOC, THREAT_ACTOR")
    entity_key: str = Field(..., description="Raw indicator or identifier value")
    display_label: str = Field(..., description="Human readable label")
    source_reference: Optional[str] = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    metadata_summary: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

class GraphEdge(BaseMongoModel):
    """Pydantic representation of a trace-grounded Attack Graph Edge."""
    edge_id: str
    organization_id: str
    source_node_id: str
    target_node_id: str
    relationship_type: str = Field(..., description="USER_USED_DEVICE, USER_CONNECTED_TO_IP, IP_RESOLVED_DOMAIN, DOMAIN_REFERENCED_URL, USER_RECEIVED_EMAIL, EMAIL_CONTAINED_URL, EVENT_INVOLVES_USER, EVENT_INVOLVES_IP, DETECTION_MATCHED_EVENT, FINDING_ESCALATED_TO_INCIDENT, HUNT_FOUND_EVENT, IOC_MATCHED_EVENT, UEBA_FLAGGED_USER")
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    confidence: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH, CONFIRMED")
    evidence_refs: List[str] = Field(default_factory=list, description="List of event or finding IDs supporting edge")
    source_system: str = Field("E11.5_INVESTIGATION")
    explanation: str = Field(..., description="Detailed text explaining evidence")

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
