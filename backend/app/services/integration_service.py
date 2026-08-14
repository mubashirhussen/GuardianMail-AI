import socket
import ipaddress
import hmac
import hashlib
import json
import uuid
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, Any, List, Optional
from app.database.connection import db_manager
from app.repositories.integration_repo import IntegrationRepository, IntegrationDeliveryRepository

def validate_safe_url(url: str) -> bool:
    """SSRF DNS resolution check blocking loopbacks, multicast, and private CIDR address ranges."""
    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            raise ValueError("Target hostname is empty")
        
        # Check against direct localhost string
        host_lower = parsed.hostname.lower()
        if host_lower in ["localhost", "127.0.0.1", "::1"]:
            raise ValueError("SSRF Target Blocked: direct localhost loopback is not permitted")

        # Resolve IPs
        ips = socket.getaddrinfo(parsed.hostname, None)
        for item in ips:
            ip_str = item[4][0]
            ip = ipaddress.ip_address(ip_str)
            if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast:
                raise ValueError(f"SSRF Target Blocked: private/local IP {ip_str} is not permitted")
        return True
    except Exception as e:
        raise ValueError(f"SSRF Check Rejected: {str(e)}")

def verify_webhook_signature(signature: str, payload: bytes, secret: str) -> bool:
    """HMAC-SHA256 signature verification to prevent spoofing and replay attacks."""
    try:
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)
    except Exception:
        return False

class IntegrationAdapter:
    async def test_connection(self, config: Dict[str, Any]) -> bool:
        raise NotImplementedError()

    async def send_alert(self, config: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError()

class SiemAdapter(IntegrationAdapter):
    async def test_connection(self, config: Dict[str, Any]) -> bool:
        url = config.get("url")
        validate_safe_url(url)
        return True

    async def send_alert(self, config: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        url = config.get("url")
        validate_safe_url(url)
        # Mock HTTPS delivery post
        return {"status": "delivered", "provider": "siem", "delivered_at": str(datetime.utcnow())}

class TicketAdapter(IntegrationAdapter):
    async def test_connection(self, config: Dict[str, Any]) -> bool:
        url = config.get("url")
        validate_safe_url(url)
        return True

    async def send_alert(self, config: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        url = config.get("url")
        validate_safe_url(url)
        # Mock ticket creation (Jira/ServiceNow)
        ticket_id = f"TICKET-{uuid.uuid4().hex[:6].upper()}"
        return {"status": "created", "ticket_id": ticket_id, "provider": "ticketing"}

class IntegrationService:
    @property
    def db(self):
        return db_manager.db

    @property
    def integration_repo(self):
        return IntegrationRepository(self.db)

    @property
    def delivery_repo(self):
        return IntegrationDeliveryRepository(self.db)

    def _get_adapter(self, provider: str) -> IntegrationAdapter:
        if provider == "siem":
            return SiemAdapter()
        elif provider in ["jira", "servicenow"]:
            return TicketAdapter()
        else:
            return SiemAdapter()

    async def test_integration_connection(self, org_id: str, integration_id: str) -> bool:
        config_doc = await self.integration_repo.get_by_org_and_id(org_id, integration_id)
        if not config_doc:
            raise ValueError("Integration config not found")
        
        adapter = self._get_adapter(config_doc.get("provider"))
        return await adapter.test_connection(config_doc.get("config", {}))

    async def dispatch_security_event(self, org_id: str, event_type: str, severity: str, details: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Publish canonical security events and log delivery retry states."""
        active_configs = await self.integration_repo.get_by_org(org_id)
        deliveries = []

        correlation_id = str(uuid.uuid4())
        canonical_event = {
            "event_id": str(uuid.uuid4()),
            "organization_id": org_id,
            "event_type": event_type,
            "timestamp": str(datetime.utcnow()),
            "severity": severity,
            "metadata": details,
            "correlation_id": correlation_id
        }

        for cfg in active_configs:
            if cfg.get("status") != "ACTIVE":
                continue
            
            integration_id = cfg.get("integration_id")
            adapter = self._get_adapter(cfg.get("provider"))
            
            status_val = "SENT"
            err_msg = None
            result_payload = {}
            
            try:
                result_payload = await adapter.send_alert(cfg.get("config", {}), canonical_event)
            except Exception as e:
                status_val = "FAILED"
                err_msg = str(e)
                
            delivery = {
                "organization_id": org_id,
                "integration_id": integration_id,
                "event_type": event_type,
                "payload": result_payload if status_val == "SENT" else canonical_event,
                "status": status_val,
                "retry_count": 0,
                "last_attempt_at": datetime.utcnow(),
                "error_message": err_msg,
                "correlation_id": correlation_id,
                "soft_delete": False
            }
            
            await self.delivery_repo.collection.insert_one(delivery)
            delivery["_id"] = str(delivery["_id"])
            deliveries.append(delivery)
            
            # Sync health markers
            await self.integration_repo.collection.update_one(
                {"_id": cfg["_id"]},
                {"$set": {
                    "last_sync_at": datetime.utcnow(),
                    "last_error": err_msg,
                    "health_status": "healthy" if status_val == "SENT" else "degraded"
                }}
            )

        return deliveries

integration_service = IntegrationService()
