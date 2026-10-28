import re
import socket
import httpx
import ipaddress
import logging
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
from app.core.config import settings

logger = logging.getLogger("guardianmail.threat_intel")

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
    def validate_ip(value: str) -> bool:
        """Validate if target is a valid IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(value.strip())
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Strict domain and hostname validation."""
        val = domain.strip().lower()
        if not val or len(val) > 253:
            return False
        
        # Remove optional trailing dot for validation
        if val.endswith('.'):
            val = val[:-1]

        # Label length validation
        labels = val.split('.')
        if len(labels) < 2:
            return False
            
        for label in labels:
            if not label or len(label) > 63:
                return False
            if label.startswith('-') or label.endswith('-'):
                return False
        
        # General hostname/Punycode validator regex
        domain_regex = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
        return bool(domain_regex.match(val))

    @staticmethod
    def validate_url(url: str) -> bool:
        """Strict URL syntax and scheme validation."""
        val = url.strip()
        if not val:
            return False
        try:
            parsed = urlparse(val if "://" in val else "http://" + val)
            if parsed.scheme.lower() not in ["http", "https"]:
                return False
            if not parsed.netloc:
                return False
            host = parsed.netloc.split(":")[0]
            if not (ThreatIntelService.validate_ip(host) or ThreatIntelService.validate_domain(host)):
                return False
            return True
        except Exception:
            return False

    @staticmethod
    def validate_hash(value: str) -> bool:
        """Strict MD5, SHA-1, or SHA-256 validation."""
        val = value.strip()
        hash_regex = re.compile(r'^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$')
        return bool(hash_regex.match(val))

    @staticmethod
    def validate_email(value: str) -> bool:
        """Strict email syntax check."""
        val = value.strip()
        email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return bool(email_regex.match(val))

    @staticmethod
    def validate_indicator(indicator_type: str, value: str) -> bool:
        """Centralized router verifying indicator by type against strict regex patterns."""
        t_clean = indicator_type.lower().strip()
        val_clean = value.strip()
        
        if t_clean in ["ipv4", "ipv6", "ip"]:
            return ThreatIntelService.validate_ip(val_clean)
        elif t_clean in ["domain", "hostname"]:
            return ThreatIntelService.validate_domain(val_clean)
        elif t_clean == "url":
            return ThreatIntelService.validate_url(val_clean)
        elif t_clean == "file_hash":
            return ThreatIntelService.validate_hash(val_clean)
        elif t_clean in ["email_address", "email"]:
            return ThreatIntelService.validate_email(val_clean)
        return False

    @staticmethod
    def normalize_indicator_value(ind_type: str, value: str) -> str:
        """Centralized normalization producing canonical indicator values."""
        t_clean = ind_type.lower().strip()
        val_clean = value.strip()
        
        if t_clean in ["ipv4", "ipv6", "ip"]:
            try:
                ip = ipaddress.ip_address(val_clean)
                return str(ip)
            except ValueError:
                return val_clean.lower()
        elif t_clean in ["domain", "hostname", "email_address", "email"]:
            norm = val_clean.lower()
            if t_clean in ["domain", "hostname"] and norm.endswith("."):
                norm = norm[:-1]
            return norm
        elif t_clean == "file_hash":
            return val_clean.lower()
        elif t_clean == "url":
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
        return val_clean

    @staticmethod
    def is_ssrf_blocked_ip(ip_str: str) -> bool:
        """Verify if a resolved IP address falls under private, loopback, link-local, or multicast networks."""
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            return (
                ip.is_private or
                ip.is_loopback or
                ip.is_link_local or
                ip.is_multicast or
                ip.is_unspecified or
                ip.is_reserved
            )
        except ValueError:
            return True

    @staticmethod
    async def expand_short_url(url: str) -> str:
        """SSRF-protected URL expander checking scheme, resolving host, validating IPs, and following redirects manually."""
        current_url = url.strip()
        max_redirects = 5
        
        for _ in range(max_redirects):
            try:
                parsed = urlparse(current_url if "://" in current_url else "http://" + current_url)
            except Exception:
                raise ValueError("SSRF block: Malformed URL target")

            scheme = parsed.scheme.lower()
            if scheme not in ["http", "https"]:
                raise ValueError(f"SSRF block: Unsupported URL scheme '{scheme}'")

            host = parsed.netloc.split(":")[0]
            if not host:
                raise ValueError("SSRF block: Missing URL hostname")

            # Resolve host to IPs
            try:
                addr_info = socket.getaddrinfo(host, None)
                ips = list({info[4][0] for info in addr_info})
            except Exception as e:
                raise ValueError(f"SSRF block: Host resolution failed: {e}")

            if not ips:
                raise ValueError("SSRF block: Host resolved to no IP addresses")

            # Inspect all resolved IPs
            for ip in ips:
                if ThreatIntelService.is_ssrf_blocked_ip(ip):
                    raise ValueError(f"SSRF block: Target resolved to private/unauthorized network: {ip}")

            # If the domain is not in shorteners list, we do not need to redirect further
            domain = parsed.netloc.lower().lstrip("www.")
            if domain not in ThreatIntelService.URL_SHORTENERS:
                return current_url

            # Request HEAD to follow redirect
            try:
                async with httpx.AsyncClient(follow_redirects=False, timeout=5.0) as client:
                    response = await client.head(current_url)
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get("Location")
                        if not location:
                            return current_url
                        # Normalize redirect target
                        if not location.startswith(("http://", "https://")):
                            from urllib.parse import urljoin
                            location = urljoin(current_url, location)
                        current_url = location
                    else:
                        return current_url
            except ValueError as e:
                # Re-raise explicit SSRF blocks
                raise e
            except Exception as e:
                logger.warning(f"URL expansion connection failed: {e}")
                return current_url

        return current_url

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
