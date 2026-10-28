import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
from bson import ObjectId

from app.database.connection import db_manager
from app.services.attack_graph_service import attack_graph_service
from app.services.campaign_service import campaign_service
from app.core.tenant_context import TenantContext

@pytest.fixture
async def setup_campaign_data():
    """Setup mock data specifically for E11.6 attack graph and campaigns tests."""
    db = db_manager.db
    org_a = "org_campaign_a"
    org_b = "org_campaign_b"

    # Clean old records
    await db["campaigns"].delete_many({})
    await db["investigations"].delete_many({})
    await db["investigation_evidence"].delete_many({})
    await db["investigation_relationships"].delete_many({})
    await db["threat_indicators"].delete_many({})
    await db["ml_features"].delete_many({})
    await db["security_telemetry"].delete_many({})
    await db["users"].delete_many({})

    # Setup User in Org A
    await db["users"].insert_one({
        "email": "analyst@campaign.com",
        "organization_id": org_a,
        "role": "soc_analyst",
        "soft_delete": False
    })

    # Setup User in Org B
    await db["users"].insert_one({
        "email": "attacker@campaign.com",
        "organization_id": org_b,
        "role": "soc_analyst",
        "soft_delete": False
    })

    # Create Org A Investigation 1
    inv1 = await db["investigations"].insert_one({
        "organization_id": org_a,
        "investigation_id": "INV-CAMP-1",
        "title": "Malicious Phish Campaign Part 1",
        "status": "OPEN",
        "severity": "HIGH",
        "priority": "HIGH",
        "created_by": "analyst@campaign.com",
        "created_at": datetime.now(timezone.utc) - timedelta(days=2),
        "soft_delete": False
    })
    inv1_id = str(inv1.inserted_id)

    # Create Org A Investigation 2
    inv2 = await db["investigations"].insert_one({
        "organization_id": org_a,
        "investigation_id": "INV-CAMP-2",
        "title": "Malicious Phish Campaign Part 2",
        "status": "OPEN",
        "severity": "HIGH",
        "priority": "HIGH",
        "created_by": "analyst@campaign.com",
        "created_at": datetime.now(timezone.utc) - timedelta(days=1),
        "soft_delete": False
    })
    inv2_id = str(inv2.inserted_id)

    # Link evidence
    for item in [
        {
            "organization_id": org_a,
            "investigation_id": "INV-CAMP-1",
            "evidence_type": "IP",
            "source_id": "8.8.8.8",
            "timestamp": datetime.now(timezone.utc),
            "added_by": "analyst@campaign.com",
            "soft_delete": False
        },
        {
            "organization_id": org_a,
            "investigation_id": "INV-CAMP-1",
            "evidence_type": "DOMAIN",
            "source_id": "malicious-phish.com",
            "timestamp": datetime.now(timezone.utc),
            "added_by": "analyst@campaign.com",
            "soft_delete": False
        },
        {
            "organization_id": org_a,
            "investigation_id": "INV-CAMP-2",
            "evidence_type": "IP",
            "source_id": "8.8.8.8",
            "timestamp": datetime.now(timezone.utc),
            "added_by": "analyst@campaign.com",
            "soft_delete": False
        }
    ]:
        await db["investigation_evidence"].insert_one(item)

    # Add E4 Threat Intel for malicious-phish.com
    await db["threat_indicators"].insert_one({
        "organization_id": org_a,
        "value": "malicious-phish.com",
        "normalized_value": "malicious-phish.com",
        "indicator_type": "domain",
        "severity": "CRITICAL",
        "description": "Active phishing Domain",
        "created_at": datetime.now(timezone.utc),
        "soft_delete": False
    })

    # Add E9 UEBA for user
    await db["ml_features"].insert_one({
        "organization_id": org_a,
        "feature_id": "FEAT-USER-RISK",
        "entity_id": "user_admin",
        "feature_name": "user_risk_score",
        "value": 0.95,
        "updated_at": datetime.now(timezone.utc),
        "soft_delete": False
    })

    return {
        "org_a": org_a,
        "org_b": org_b,
        "inv1_id": inv1_id,
        "inv2_id": inv2_id
    }

@pytest.mark.anyio
async def test_attack_graph_construction_and_enrichment(setup_campaign_data):
    """Verify graph constructions fetch indicators, UEBA values, and handle depth parameters."""
    org_a = setup_campaign_data["org_a"]
    inv1_id = setup_campaign_data["inv1_id"]

    # Build Graph with depth 2
    graph = await attack_graph_service.build_graph_for_investigation(org_a, "INV-CAMP-1", max_depth=2)
    assert "nodes" in graph
    assert "edges" in graph
    
    # Assert nodes and edges were added
    nodes = graph["nodes"]
    assert len(nodes) >= 2

    # Check E4 Enrichment
    domain_node = next((n for n in nodes if n["label"] == "malicious-phish.com"), None)
    assert domain_node is not None
    assert domain_node["metadata"]["threat_intel_reputation"] == "CRITICAL"
    assert "Active phishing Domain" in domain_node["metadata"]["threat_intel_description"]

    # Check that it traversed and found INV-CAMP-2 via shared IP "8.8.8.8"
    shared_inv_node = next((n for n in nodes if n["id"] == "INV-INV-CAMP-2"), None)
    assert shared_inv_node is not None

@pytest.mark.anyio
async def test_attack_graph_cycle_protection(setup_campaign_data):
    """Assert cyclic links do not cause infinite recursion in depth traversal."""
    db = db_manager.db
    org_a = setup_campaign_data["org_a"]

    # Insert a cyclic relationship
    for item in [
        {
            "organization_id": org_a,
            "investigation_id": "INV-CAMP-1",
            "source_type": "IP",
            "source_id": "8.8.8.8",
            "target_type": "DOMAIN",
            "target_id": "malicious-phish.com",
            "relationship_type": "IP_RESOLVED_DOMAIN",
            "confidence": "HIGH",
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        },
        {
            "organization_id": org_a,
            "investigation_id": "INV-CAMP-1",
            "source_type": "DOMAIN",
            "source_id": "malicious-phish.com",
            "target_type": "IP",
            "target_id": "8.8.8.8",
            "relationship_type": "DOMAIN_RESOLVED_IP",
            "confidence": "HIGH",
            "timestamp": datetime.now(timezone.utc),
            "soft_delete": False
        }
    ]:
        await db["investigation_relationships"].insert_one(item)

    # Build Graph, cycle must execute safely
    graph = await attack_graph_service.build_graph_for_investigation(org_a, "INV-CAMP-1", max_depth=3)
    assert "nodes" in graph
    assert len(graph["nodes"]) > 0

@pytest.mark.anyio
async def test_campaign_crud_and_status_validation(setup_campaign_data):
    """Verify manual campaign case container updates enforce state transitions."""
    org_a = setup_campaign_data["org_a"]

    # Create manually
    camp = await campaign_service.create_campaign(
        org_id=org_a,
        name="APT29 Infrastructure overlap",
        description="Suspicious correlation detected across domains",
        status="SUSPECTED",
        confidence="medium",
        analyst_id="analyst@campaign.com"
    )
    assert camp["name"] == "APT29 Infrastructure overlap"
    assert camp["status"] == "SUSPECTED"

    # Add Note
    updated = await campaign_service.add_note(
        org_id=org_a,
        campaign_id=camp["campaign_id"],
        content="This campaign matches techniques mapped under T1566 Phishing",
        author_id="analyst@campaign.com"
    )
    assert len(updated["notes"]) == 1
    assert updated["notes"][0]["content"] == "This campaign matches techniques mapped under T1566 Phishing"

    # Update Status
    updated = await campaign_service.update_campaign(
        org_id=org_a,
        campaign_id=camp["campaign_id"],
        update_data={"status": "CONFIRMED", "confidence": "high"},
        analyst_id="analyst@campaign.com"
    )
    assert updated["status"] == "CONFIRMED"
    assert updated["confidence"] == "high"

    # Invalid status must raise ValueError
    with pytest.raises(ValueError):
        await campaign_service.update_campaign(
            org_id=org_a,
            campaign_id=camp["campaign_id"],
            update_data={"status": "INVALID_STATE"},
            analyst_id="analyst@campaign.com"
        )

@pytest.mark.anyio
async def test_campaign_correlation_scanner(setup_campaign_data):
    """Assert scanner runs and groups investigations based on shared indicators."""
    org_a = setup_campaign_data["org_a"]

    # Run scan
    res = await campaign_service.run_campaign_correlation_scan(org_a)
    assert res["status"] == "SUCCESS"
    assert res["campaigns_discovered"] == 1

    # Verify campaign was inserted
    db = db_manager.db
    camp = await db["campaigns"].find_one({"organization_id": org_a, "status": "SUSPECTED"})
    assert camp is not None
    assert "8.8.8.8" in camp["indicators"]
    assert "INV-CAMP-1" in camp["related_investigations"]
    assert "INV-CAMP-2" in camp["related_investigations"]

@pytest.mark.anyio
async def test_campaigns_and_graph_multi_tenant_isolation(setup_campaign_data):
    """Validate Org A cannot access or modify Org B graph and campaigns data."""
    org_a = setup_campaign_data["org_a"]
    org_b = setup_campaign_data["org_b"]

    # Create campaign in Org A
    camp_a = await campaign_service.create_campaign(
        org_id=org_a,
        name="Org A Case Campaign",
        description="Org A Campaign Case",
        status="SUSPECTED",
        confidence="medium",
        analyst_id="analyst@campaign.com"
    )

    # Attempt to retrieve Org A campaign using Org B token context (Must return empty / raise error)
    workspace = await campaign_service.get_campaign_workspace(org_b, camp_a["campaign_id"])
    assert workspace == {}

    # Attempt to build Org A graph using Org B context (Must raise ValueError)
    with pytest.raises(ValueError):
        await attack_graph_service.build_graph_for_investigation(org_b, "INV-CAMP-1")
