import re
import socket
import httpx
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
from app.core.config import settings

class ThreatIntelService:
    # URL Shorteners List
    URL_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link",
        "tiny.cc", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    }
    
    # Trusted Brands for TypoSquatting comparison
    TRUSTED_BRANDS = {
        "google.com", "gmail.com", "microsoft.com", "outlook.com", "apple.com",
        "amazon.com", "paypal.com", "facebook.com", "twitter.com", "linkedin.com",
        "github.com", "dropbox.com", "icloud.com", "yahoo.com", "hotmail.com",
    }

    @staticmethod
    async def expand_short_url(url: str) -> str:
        """Expand shortened URLs by tracking redirects using HTTP HEAD request (Module 7)."""
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc.lower().lstrip("www.")
        
        if domain not in ThreatIntelService.URL_SHORTENERS:
            return url
            
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=5.0) as client:
                response = await client.head(url)
                return str(response.url)
        except Exception:
            return url  # Fallback to original URL if expansion fails

    @staticmethod
    def check_typosquatting(domain: str) -> Tuple[bool, Optional[str]]:
        """Compare domain name to trusted brands to identify lookalike domains (Module 7)."""
        # Exclude exact matches
        if domain in ThreatIntelService.TRUSTED_BRANDS:
            return False, None
            
        base_domain = domain.split(".")[0]
        for brand in ThreatIntelService.TRUSTED_BRANDS:
            brand_base = brand.split(".")[0]
            if len(base_domain) > 3 and len(brand_base) > 3:
                # Count character alignment matches
                matches = sum(c1 == c2 for c1, c2 in zip(base_domain, brand_base))
                similarity = matches / max(len(base_domain), len(brand_base))
                if similarity > 0.75:
                    return True, brand
        return False, None

    @staticmethod
    def is_unicode_homograph(domain: str) -> bool:
        """Detect internationalized domain names (IDN/Punycode) indicating homograph spoofing (Module 7)."""
        # Homograph attacks typically use Punycode representation starting with 'xn--'
        if domain.lower().startswith("xn--"):
            return True
            
        # Check if contains non-ascii characters (some clients don't convert to punycode)
        try:
            domain.encode("ascii")
            return False
        except UnicodeEncodeError:
            return True

    @staticmethod
    async def check_url_reputation(url: str) -> Dict[str, Any]:
        """Perform URL reputation validation via VirusTotal API or fallback heuristic scanning (Module 6 & 7)."""
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc.lower().lstrip("www.")
        
        result = {
            "url": url,
            "domain": domain,
            "is_shortener": domain in ThreatIntelService.URL_SHORTENERS,
            "is_ip_address": bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain)),
            "is_typosquatting": False,
            "spoofed_brand": None,
            "is_homograph": ThreatIntelService.is_unicode_homograph(domain),
            "reputation_score": 0.0,
            "vt_scan_result": "Clean (Local Heuristics)",
            "urlscan_result": "Clean (Local Heuristics)"
        }

        # Check typosquatting
        typo, brand = ThreatIntelService.check_typosquatting(domain)
        if typo:
            result["is_typosquatting"] = True
            result["spoofed_brand"] = brand
            result["reputation_score"] = 70.0  # High initial risk score

        # Query VirusTotal if API Key is configured
        if settings.VIRUSTOTAL_API_KEY:
            try:
                # VirusTotal v3 URL Scan API
                headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
                async with httpx.AsyncClient(timeout=5.0) as client:
                    # In VT v3 we first check domain / base64 of URL
                    # For simplicity, query the domain report
                    url_vt = f"https://www.virustotal.com/api/v3/domains/{domain}"
                    response = await client.get(url_vt, headers=headers)
                    if response.status_code == 200:
                        data = response.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        
                        if malicious > 0:
                            result["reputation_score"] = max(result["reputation_score"], 90.0)
                            result["vt_scan_result"] = f"Malicious ({malicious} detections)"
                        elif suspicious > 0:
                            result["reputation_score"] = max(result["reputation_score"], 50.0)
                            result["vt_scan_result"] = f"Suspicious ({suspicious} detections)"
                        else:
                            result["vt_scan_result"] = "Clean (VirusTotal API)"
            except Exception:
                pass

        return result

    @staticmethod
    def get_dns_analysis(domain: str) -> Dict[str, Any]:
        """Perform basic DNS and IP validation (Module 6)."""
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            return {
                "resolved": True,
                "ips": ips,
                "message": f"Resolved successfully to {len(ips)} IPs"
            }
        except Exception as e:
            return {
                "resolved": False,
                "ips": [],
                "message": f"DNS resolution failed: {e}"
            }
