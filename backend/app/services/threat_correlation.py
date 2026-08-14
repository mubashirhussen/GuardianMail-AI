import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from app.database.connection import db_manager
from app.repositories.threat_intelligence_repo import (
    ThreatIndicatorRepository, ThreatCampaignRepository, ThreatObservationRepository
)
from app.repositories.audit_repo import AuditRepository
from app.services.threat_intel_provider import adapters

logger = logging.getLogger("guardianmail.threat_correlation")

class ThreatCorrelationService:
    """Ingests threat indicators, executes provider enrichment, runs confidence scoring, and correlates campaigns."""

    def __init__(self):
        pass

    @property
    def indicator_repo(self) -> ThreatIndicatorRepository:
        return ThreatIndicatorRepository(db_manager.db)

    @property
    def campaign_repo(self) -> ThreatCampaignRepository:
        return ThreatCampaignRepository(db_manager.db)

    @property
    def observation_repo(self) -> ThreatObservationRepository:
        return ThreatObservationRepository(db_manager.db)

    @property
    def audit_repo(self) -> AuditRepository:
        return AuditRepository(db_manager.db)

    def normalize_indicator(self, ind_type: str, value: str) -> str:
        """Standardize indicator values to prevent duplicates (e.g. lowercase domains, trim hashes)."""
        val_clean = str(value).strip()
        ind_type_clean = ind_type.lower().strip()
        
        if ind_type_clean in ["domain", "email_address", "hostname"]:
            return val_clean.lower()
        elif ind_type_clean == "url":
            # Normalize URL domain portion to lowercase, keep paths case sensitive
            if "://" in val_clean:
                parts = val_clean.split("://", 1)
                scheme = parts[0].lower()
                rest = parts[1]
                if "/" in rest:
                    domain, path = rest.split("/", 1)
                    return f"{scheme}://{domain.lower()}/{path}"
                else:
                    return f"{scheme}://{rest.lower()}"
            return val_clean.lower()
        elif ind_type_clean == "file_hash":
            return val_clean.lower() # MD5/SHA256 lowercase
            
        return val_clean

    async def ingest_indicator(
        self,
        indicator_type: str,
        indicator_value: str,
        source: str,
        organization_id: Optional[str] = None,
        tags: List[str] = None,
        description: Optional[str] = None,
        expires_in_days: int = 30
    ) -> Dict[str, Any]:
        """Ingest single indicator running validation, normalization, deduplication, enrichment and scoring (Idempotent)."""
        norm_val = self.normalize_indicator(indicator_type, indicator_value)
        tags = tags or []
        
        # 1. Deduplication / Check if already exists in DB
        existing = await self.indicator_repo.get_by_value(indicator_type, norm_val, organization_id)
        now = datetime.now(timezone.utc)
        
        # Enforce lifecycle dates
        expires_at = now + timedelta(days=expires_in_days)
        
        if existing:
            # Update last seen and expires_at
            update_data = {
                "last_seen": now,
                "expires_at": expires_at,
                "updated_at": now
            }
            if tags:
                # Merge tags
                merged_tags = list(set(existing.get("tags", []) + tags))
                update_data["tags"] = merged_tags
                
            await self.indicator_repo.collection.update_one(
                {"_id": self.indicator_repo._to_oid(existing["_id"])},
                {"$set": update_data}
            )
            existing.update(update_data)
            return existing

        # 2. Enrich indicator utilizing registered threat adapters
        enrichment_data = await self.enrich_indicator(indicator_type, norm_val)
        
        # 3. Calculate Confidence Score and Severity Verdict
        score_data = self.calculate_scores(indicator_type, enrichment_data)
        
        # 4. Insert new Indicator document
        new_ioc = {
            "organization_id": organization_id,
            "indicator_type": indicator_type.lower().strip(),
            "indicator_value": indicator_value,
            "normalized_value": norm_val,
            "first_seen": now,
            "last_seen": now,
            "confidence": score_data["confidence"],
            "severity": score_data["severity"],
            "status": "ACTIVE",
            "source": source,
            "tags": tags,
            "description": description or f"Enriched IOC from {source}",
            "created_at": now,
            "updated_at": now,
            "expires_at": expires_at
        }
        
        created = await self.indicator_repo.create(new_ioc)
        created["_id"] = str(created["_id"])
        
        # Trigger audit logging
        await self.audit_repo.create({
            "organization_id": organization_id or "system_global",
            "user_id": "system_pipeline",
            "action": "IOC_CREATED",
            "details": {"indicator_id": created["_id"], "value": norm_val, "type": indicator_type},
            "created_at": now
        })
        
        # Run Campaign correlation logic asynchronously
        await self.correlate_indicator(created)
        
        return created

    async def enrich_indicator(self, ind_type: str, value: str) -> Dict[str, Any]:
        """Queries VirusTotal, AbuseIPDB, URLhaus, AlienVault for IOC enrichment statistics."""
        data = {}
        
        # Query VirusTotal
        vt = adapters.get("virustotal")
        if vt:
            vt_res = await vt.lookup(ind_type, value)
            if vt_res:
                data["virustotal"] = vt_res
                
        # Query AbuseIPDB for IP objects
        if ind_type in ["ipv4", "ipv6"]:
            ab = adapters.get("abuseipdb")
            if ab:
                ab_res = await ab.lookup(ind_type, value)
                if ab_res:
                    data["abuseipdb"] = ab_res
                    
        # Query URLhaus for URL indicators
        if ind_type == "url":
            uh = adapters.get("urlhaus")
            if uh:
                uh_res = await uh.lookup(ind_type, value)
                if uh_res:
                    data["urlhaus"] = uh_res
                    
        # Query AlienVault pulse counts
        av = adapters.get("alienvault")
        if av:
            av_res = await av.lookup(ind_type, value)
            if av_res:
                data["alienvault"] = av_res
                
        return data

    def calculate_scores(self, ind_type: str, enrichment: Dict[str, Any]) -> Dict[str, Any]:
        """Determines compound explainable confidence and severity scores from feed signals."""
        confidence = 50
        severity = "medium"
        
        vt = enrichment.get("virustotal", {})
        abuse = enrichment.get("abuseipdb", {})
        urlhaus = enrichment.get("urlhaus", {})
        vault = enrichment.get("alienvault", {})
        
        # Confidence calculation
        sources_reporting = 0
        if vt.get("detected"):
            confidence += 20
            sources_reporting += 1
        if abuse.get("abuseConfidenceScore", 0) > 20:
            confidence += 15
            sources_reporting += 1
        if urlhaus.get("query_status") == "ok":
            confidence += 25
            sources_reporting += 1
        if vault.get("pulse_count", 0) > 0:
            confidence += 15
            sources_reporting += 1

        # Clip confidence bounds
        confidence = min(max(confidence, 0), 100)
        
        # Severity assignment
        vt_pos = vt.get("positives", 0)
        abuse_score = abuse.get("abuseConfidenceScore", 0)
        
        if vt_pos > 20 or abuse_score > 85 or urlhaus.get("threat") == "malware_download":
            severity = "critical"
        elif vt_pos > 5 or abuse_score > 40 or vault.get("pulse_count", 0) > 3:
            severity = "high"
        elif vt_pos > 0 or abuse_score > 0 or vault.get("pulse_count", 0) > 0:
            severity = "medium"
        else:
            severity = "low"
            
        return {"confidence": confidence, "severity": severity}

    async def record_observation(
        self,
        org_id: str,
        indicator_id: str,
        email_id: Optional[str] = None,
        user_id: Optional[str] = None,
        incident_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Record an observed instance of a threat indicator in scanning operations."""
        observation = {
            "organization_id": org_id,
            "indicator_id": indicator_id,
            "observed_at": datetime.now(timezone.utc),
            "email_id": email_id,
            "user_id": user_id,
            "incident_id": incident_id
        }
        created = await self.observation_repo.create(observation)
        created["_id"] = str(created["_id"])
        return created

    async def correlate_indicator(self, indicator: Dict[str, Any]) -> None:
        """Run threat correlation linking related domains, URLs, and IPs to active campaigns."""
        org_id = indicator.get("organization_id")
        tags = indicator.get("tags", [])
        
        # Look for existing indicators sharing similar infrastructure tags
        if not tags:
            return
            
        # Find matching indicators
        query = self.indicator_repo._apply_soft_delete_filter({
            "organization_id": org_id,
            "tags": {"$in": tags},
            "_id": {"$ne": self.indicator_repo._to_oid(indicator["_id"])}
        })
        
        cursor = self.indicator_repo.collection.find(query)
        matching_iocs = await cursor.to_list(length=10)
        
        if len(matching_iocs) >= 2:
            # We have identified a pattern of at least 3 matching indicators (including the newly ingested one)
            # Link them under a suspected threat campaign
            campaign_name = f"Campaign Associated with Tags: {', '.join(tags[:2])}"
            now = datetime.now(timezone.utc)
            
            # Check if campaign already exists
            existing_campaign = await self.campaign_repo.collection.find_one({
                "organization_id": org_id,
                "name": campaign_name
            })
            
            ioc_ids = [str(ioc["_id"]) for ioc in matching_iocs] + [str(indicator["_id"])]
            
            if existing_campaign:
                # Merge indicators list
                merged_iocs = list(set(existing_campaign.get("indicators", []) + ioc_ids))
                await self.campaign_repo.collection.update_one(
                    {"_id": existing_campaign["_id"]},
                    {
                        "$set": {
                            "indicators": merged_iocs,
                            "last_seen": now,
                            "confidence": min(existing_campaign.get("confidence", 50) + 10, 95)
                        }
                    }
                )
                logger.info(f"Updated Campaign '{campaign_name}' with correlated indicators.")
            else:
                # Create campaign record
                campaign_payload = {
                    "organization_id": org_id,
                    "name": campaign_name,
                    "description": f"Automated correlation campaign triggered by shared infrastructure tags: {tags}",
                    "confidence": 65,
                    "severity": indicator.get("severity", "medium"),
                    "status": "suspected",
                    "first_seen": now,
                    "last_seen": now,
                    "indicators": ioc_ids,
                    "incidents": [],
                    "techniques": ["T1566"] # MITRE ATT&CK Default credential access phishing tactic reference
                }
                await self.campaign_repo.create(campaign_payload)
                logger.info(f"Created Suspected Campaign '{campaign_name}' with {len(ioc_ids)} indicators.")

threat_correlation_service = ThreatCorrelationService()
