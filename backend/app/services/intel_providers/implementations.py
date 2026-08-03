import httpx
import re
import socket
import logging
from typing import Any, Dict
from app.config.settings import settings
from app.services.intel_providers.base import BaseIntelProvider
from app.services.domain_intel import DomainIntelService

logger = logging.getLogger(__name__)

class GoogleSafeBrowsingProvider(BaseIntelProvider):
    """Google Safe Browsing API threat intelligence lookup service."""
    
    async def initialize(self) -> None:
        pass
        
    async def lookup(self, indicator: str) -> Dict[str, Any]:
        api_key = getattr(settings, "SAFE_BROWSING_API_KEY", "")
        if not api_key:
             return {"status": "skipped", "reason": "API Key not configured"}
             
        cached = await self.get_cached(indicator)
        if cached:
             return cached
             
        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {"clientId": "guardianmail", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": indicator}]
            }
        }
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout()) as client:
                res = await client.post(url, json=payload)
                if res.status_code == 200:
                    normalized = self.normalize(res.json())
                    await self.set_cached(indicator, normalized)
                    return normalized
        except Exception as e:
            logger.error(f"Google Safe Browsing request failed: {str(e)}")
            
        return {"status": "unknown", "malicious": False}

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        matches = raw_data.get("matches", [])
        if matches:
             return {
                 "status": "completed",
                 "malicious": True,
                 "verdict": "phishing",
                 "details": f"Flagged by Google Safe Browsing: {matches[0].get('threatType')}"
             }
        return {"status": "completed", "malicious": False, "verdict": "safe"}

    async def health_check(self) -> bool:
        return True

    def confidence(self) -> float:
        return 0.95


class VirusTotalProvider(BaseIntelProvider):
    """VirusTotal URL and file hash scanning reputation service."""
    
    async def initialize(self) -> None:
        pass
        
    async def lookup(self, indicator: str) -> Dict[str, Any]:
        api_key = getattr(settings, "VIRUSTOTAL_API_KEY", "")
        if not api_key:
             return {"status": "skipped", "reason": "API Key not configured"}
             
        cached = await self.get_cached(indicator)
        if cached:
             return cached
             
        # Check if URL or hash
        is_url = indicator.startswith(("http://", "https://"))
        url = "https://www.virustotal.com/api/v3/urls" if is_url else f"https://www.virustotal.com/api/v3/files/{indicator}"
        headers = {"x-apikey": api_key}
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout()) as client:
                if is_url:
                     # For URLs, VT requires base64 URL identifier or post first, let's keep it simple
                     # or check URL reputation endpoint
                     import base64
                     url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
                     url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                     res = await client.get(url, headers=headers)
                else:
                     res = await client.get(url, headers=headers)
                     
                if res.status_code == 200:
                    normalized = self.normalize(res.json())
                    await self.set_cached(indicator, normalized)
                    return normalized
        except Exception as e:
            logger.error(f"VirusTotal lookup failed: {str(e)}")
            
        return {"status": "unknown", "malicious": False}

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        stats = raw_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        
        is_malicious = malicious_count >= 3
        return {
            "status": "completed",
            "malicious": is_malicious,
            "verdict": "malware" if is_malicious else "safe",
            "details": f"VirusTotal malicious engine checks count: {malicious_count}/{sum(stats.values())}"
        }

    async def health_check(self) -> bool:
        return True

    def confidence(self) -> float:
        return 0.90


class AbuseIPDBProvider(BaseIntelProvider):
    """AbuseIPDB network host and IP reputation service."""
    
    async def initialize(self) -> None:
        pass
        
    async def lookup(self, indicator: str) -> Dict[str, Any]:
        api_key = getattr(settings, "ABUSEIPDB_API_KEY", "")
        if not api_key:
             return {"status": "skipped", "reason": "API Key not configured"}
             
        cached = await self.get_cached(indicator)
        if cached:
             return cached
             
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {"ipAddress": indicator, "maxAgeInDays": "90"}
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout()) as client:
                res = await client.get(url, headers=headers, params=params)
                if res.status_code == 200:
                    normalized = self.normalize(res.json())
                    await self.set_cached(indicator, normalized)
                    return normalized
        except Exception as e:
            logger.error(f"AbuseIPDB check failed: {str(e)}")
            
        return {"status": "unknown", "malicious": False}

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        data = raw_data.get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        is_malicious = score >= 50
        return {
            "status": "completed",
            "malicious": is_malicious,
            "verdict": "spam" if is_malicious else "safe",
            "details": f"AbuseIPDB Abuse Confidence Score: {score}%"
        }

    async def health_check(self) -> bool:
        return True

    def confidence(self) -> float:
        return 0.85


class DNSWhoisProvider(BaseIntelProvider):
    """Heuristic WHOIS domain age and MX/A record verification provider."""
    
    async def initialize(self) -> None:
        pass
        
    async def lookup(self, indicator: str) -> Dict[str, Any]:
        # Leverage existing DomainIntelService for DNS lookup age checks
        cached = await self.get_cached(indicator)
        if cached:
             return cached
             
        try:
             res = await DomainIntelService.get_domain_intelligence(indicator)
             normalized = self.normalize(res)
             await self.set_cached(indicator, normalized)
             return normalized
        except Exception as e:
             logger.error(f"DNSWhois lookup failed: {str(e)}")
        return {"status": "unknown", "malicious": False}

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        age_days = raw_data.get("age_days", 365)
        # Domain registered in the last 14 days is flagged as suspicious
        is_suspicious = age_days <= 14
        return {
            "status": "completed",
            "malicious": is_suspicious,
            "verdict": "suspicious" if is_suspicious else "safe",
            "details": f"Domain registration age: {age_days} days (Registrar: {raw_data.get('registrar')})"
        }

    async def health_check(self) -> bool:
        return True

    def confidence(self) -> float:
        return 0.80


class IPGeoProvider(BaseIntelProvider):
    """IP address country and network ASN geolocation lookup service."""
    
    async def initialize(self) -> None:
        pass
        
    async def lookup(self, indicator: str) -> Dict[str, Any]:
        cached = await self.get_cached(indicator)
        if cached:
             return cached
             
        # Free geoip lookup service
        url = f"https://ipapi.co/{indicator}/json/"
        try:
            async with httpx.AsyncClient(timeout=self.timeout()) as client:
                res = await client.get(url)
                if res.status_code == 200:
                    normalized = self.normalize(res.json())
                    await self.set_cached(indicator, normalized)
                    return normalized
        except Exception as e:
            logger.error(f"IPGeo lookup failed: {str(e)}")
            
        return {"status": "unknown", "malicious": False}

    def normalize(self, raw_data: Any) -> Dict[str, Any]:
        country = raw_data.get("country_name", "Unknown Country")
        org = raw_data.get("org", "Unknown ASN")
        return {
            "status": "completed",
            "malicious": False,
            "verdict": "safe",
            "details": f"Location: {country} (Network Org: {org})"
        }

    async def health_check(self) -> bool:
        return True

    def confidence(self) -> float:
        return 0.70
