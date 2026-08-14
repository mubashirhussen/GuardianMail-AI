import logging
import asyncio
from typing import Optional, Dict, Any
from app.database.cache import cache_manager

logger = logging.getLogger("guardianmail.threat_intel_provider")

class BaseThreatIntelAdapter:
    """Abstract base class establishing provider interfaces, cache mapping rules, and error policies."""
    
    def __init__(self, provider_name: str, cache_ttl_seconds: int = 3600):
        self.provider_name = provider_name
        self.cache_ttl = cache_ttl_seconds

    async def lookup(self, indicator_type: str, value: str) -> Optional[Dict[str, Any]]:
        """Fetch enrichment metrics from local Redis cache or invoke raw client lookups."""
        cache_key = f"provider_cache:{self.provider_name}:{indicator_type}:{value}"
        cached = await cache_manager.get(cache_key)
        if cached:
            return cached

        # Execute client lookup with retry framework
        attempts = 3
        result = None
        for attempt in range(attempts):
            try:
                result = await asyncio.wait_for(
                    self._execute_lookup(indicator_type, value), 
                    timeout=5.0
                )
                break
            except Exception as e:
                logger.warning(
                    f"Provider '{self.provider_name}' lookup failed (Attempt {attempt+1}/{attempts}) for "
                    f"'{value}': {str(e)}"
                )
                if attempt < attempts - 1:
                    await asyncio.sleep(0.5)

        if result:
            await cache_manager.set(cache_key, result, expire_seconds=self.cache_ttl)
            
        return result

    async def _execute_lookup(self, indicator_type: str, value: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError()

class VirusTotalAdapter(BaseThreatIntelAdapter):
    def __init__(self):
        super().__init__("VirusTotal", cache_ttl_seconds=3600)

    async def _execute_lookup(self, indicator_type: str, value: str) -> Optional[Dict[str, Any]]:
        val_lower = value.lower().strip()
        # Mock detection rules
        is_malicious = False
        positives = 0
        total = 68
        
        if indicator_type == "file_hash":
            if "malicious" in val_lower or val_lower == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
                is_malicious = True
                positives = 42
        elif indicator_type in ["domain", "url"]:
            if "malicious" in val_lower or "phish" in val_lower or "test-malware" in val_lower:
                is_malicious = True
                positives = 15

        if is_malicious:
            return {
                "detected": True,
                "positives": positives,
                "total": total,
                "scan_date": "2026-08-08",
                "classification": "Phishing/Malware Variant" if indicator_type == "file_hash" else "Malicious Infrastructure"
            }
        return {"detected": False, "positives": 0, "total": total}

class AbuseIPDBAdapter(BaseThreatIntelAdapter):
    def __init__(self):
        super().__init__("AbuseIPDB", cache_ttl_seconds=3600)

    async def _execute_lookup(self, indicator_type: str, value: str) -> Optional[Dict[str, Any]]:
        if indicator_type not in ["ipv4", "ipv6"]:
            return None
            
        val_lower = value.lower().strip()
        abuse_score = 0
        country_code = "US"
        usage_type = "Commercial"
        
        if "192.168" in val_lower or "10.0" in val_lower:
            # internal subnet
            country_code = "ZZ"
            usage_type = "Private IP"
        elif "1.2.3.4" in val_lower or "99.99.99.99" in val_lower:
            abuse_score = 100
            country_code = "CN"
            usage_type = "Botnet Command Control"

        return {
            "abuseConfidenceScore": abuse_score,
            "countryCode": country_code,
            "usageType": usage_type,
            "totalReports": 240 if abuse_score > 0 else 0
        }

class URLhausAdapter(BaseThreatIntelAdapter):
    def __init__(self):
        super().__init__("URLhaus", cache_ttl_seconds=1800)

    async def _execute_lookup(self, indicator_type: str, value: str) -> Optional[Dict[str, Any]]:
        if indicator_type != "url":
            return None
            
        val_lower = value.lower().strip()
        if "malicious" in val_lower or "phish" in val_lower or "test-malware" in val_lower:
            return {
                "query_status": "ok",
                "url_status": "online",
                "threat": "malware_download",
                "tags": ["trojan", "stealer", "infostealer"]
            }
        return {"query_status": "no_match"}

class AlienVaultAdapter(BaseThreatIntelAdapter):
    def __init__(self):
        super().__init__("AlienVault", cache_ttl_seconds=3600)

    async def _execute_lookup(self, indicator_type: str, value: str) -> Optional[Dict[str, Any]]:
        val_lower = value.lower().strip()
        pulse_count = 0
        
        if "malicious" in val_lower or "phish" in val_lower or "test-malware" in val_lower or "1.2.3.4" in val_lower:
            pulse_count = 8

        return {
            "pulse_count": pulse_count,
            "tags": ["threat_actor_x", "phishing_campaign"] if pulse_count > 0 else []
        }

# Adapter Registry
adapters = {
    "virustotal": VirusTotalAdapter(),
    "abuseipdb": AbuseIPDBAdapter(),
    "urlhaus": URLhausAdapter(),
    "alienvault": AlienVaultAdapter()
}
