from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import re
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.base import BaseRepository

def parse_user_agent_details(user_agent: str = "") -> Dict[str, str]:
    """Parse User-Agent string to extract friendly device name, browser, OS, and form factor."""
    ua = user_agent.lower()
    
    # Form Factor / Device Type
    if "mobile" in ua or "android" in ua or "iphone" in ua or "ipod" in ua:
        device_type = "mobile"
    elif "tablet" in ua or "ipad" in ua:
        device_type = "tablet"
    else:
        device_type = "desktop"

    # OS Identification
    if "windows" in ua:
        if "windows nt 10.0" in ua:
            os_name = "Windows"
        else:
            os_name = "Windows"
    elif "iphone" in ua or "ipad" in ua or "ios" in ua:
        os_name = "iOS"
    elif "android" in ua:
        os_name = "Android"
    elif "macintosh" in ua or "mac os" in ua:
        os_name = "macOS"
    elif "linux" in ua:
        os_name = "Linux"
    else:
        os_name = "Desktop OS"

    # Browser Identification
    if "edg/" in ua or "edge/" in ua:
        browser_name = "Edge"
    elif "chrome/" in ua or "crios/" in ua:
        browser_name = "Chrome"
    elif "firefox/" in ua or "fxios/" in ua:
        browser_name = "Firefox"
    elif "safari/" in ua and "chrome/" not in ua:
        browser_name = "Safari"
    elif "opera/" in ua or "opr/" in ua:
        browser_name = "Opera"
    else:
        browser_name = "Chrome"

    # Formulate human-friendly device name
    if device_type == "mobile":
        if os_name == "iOS":
            device_name = "Apple iPhone"
        elif os_name == "Android":
            device_name = "Android Mobile"
        else:
            device_name = "Mobile Device"
    elif device_type == "tablet":
        device_name = "iPad / Tablet"
    else:
        if os_name == "Windows":
            device_name = "Windows Workstation"
        elif os_name == "macOS":
            device_name = "MacBook Pro"
        else:
            device_name = f"{os_name} PC"

    return {
        "device_type": device_type,
        "os": os_name,
        "browser": browser_name,
        "device_name": device_name
    }


def evaluate_session_risk(ip_address: str, is_trusted: bool, is_suspicious: bool = False) -> str:
    """Evaluate session security posture: LOW, MEDIUM, or HIGH."""
    if is_suspicious:
        return "HIGH"
    if is_trusted:
        return "LOW"
    # Localhost, private dev networks, or verified 2FA sessions are secure
    if ip_address in ("127.0.0.1", "::1") or ip_address.startswith("192.168.") or ip_address.startswith("10."):
        return "LOW"
    return "MEDIUM"


class DeviceRepository(BaseRepository):
    def __init__(self, db: AsyncIOMotorDatabase):
        super().__init__(db, "devices")
        # Sessions collection for active JWT tokens
        self.sessions_collection = db["sessions"]

    async def get_trusted_device(self, user_id: str, fingerprint_hash: str) -> Optional[Dict[str, Any]]:
        """Fetch device metadata for user and fingerprint."""
        device = await self.collection.find_one({
            "user_id": user_id,
            "fingerprint_hash": fingerprint_hash
        })
        if device:
            device["_id"] = str(device["_id"])
        return device

    async def register_device(
        self, 
        user_id: str, 
        fingerprint_hash: str, 
        device_name: Optional[str] = None, 
        user_agent: str = "", 
        ip_address: str = "127.0.0.1",
        is_trusted: bool = False
    ) -> Dict[str, Any]:
        """Register device or update last active time of a device with rich metadata."""
        now = datetime.now(timezone.utc)
        device_id = fingerprint_hash or "default_device"
        ua_traits = parse_user_agent_details(user_agent)
        
        final_device_name = device_name or ua_traits["device_name"]
        
        location = "Local Network (Authorized)" if ip_address in ("127.0.0.1", "::1") else "Detected Region"
        
        device_data = {
            "user_id": user_id,
            "device_id": device_id,
            "fingerprint_hash": fingerprint_hash,
            "device_name": final_device_name,
            "device_type": ua_traits["device_type"],
            "browser": ua_traits["browser"],
            "os": ua_traits["os"],
            "user_agent": user_agent,
            "last_login_ip": ip_address,
            "location": location,
            "last_used_at": now,
            "soft_delete": False
        }
        
        try:
            existing = await self.collection.find_one({"user_id": user_id, "fingerprint_hash": fingerprint_hash})
            if existing:
                await self.collection.update_one(
                    {"_id": existing["_id"]},
                    {"$set": device_data}
                )
                device_data["_id"] = str(existing["_id"])
                device_data["is_trusted"] = existing.get("is_trusted", is_trusted)
            else:
                device_data["is_trusted"] = is_trusted
                device_data["created_at"] = now
                result = await self.collection.insert_one(device_data)
                device_data["_id"] = str(result.inserted_id)
        except Exception:
            device_data["_id"] = fingerprint_hash
            device_data["is_trusted"] = is_trusted
            
        return device_data

    async def trust_device(self, user_id: str, fingerprint_hash: str, trust: bool = True) -> bool:
        """Mark device as trusted and update associated sessions."""
        result = await self.collection.update_one(
            {"user_id": user_id, "fingerprint_hash": fingerprint_hash},
            {"$set": {"is_trusted": trust, "trust_date": datetime.now(timezone.utc)}}
        )
        return result.modified_count > 0 or result.matched_count > 0

    async def create_session(
        self, 
        user_id: str, 
        token_id: str, 
        fingerprint_hash: str, 
        ip_address: str, 
        user_agent: str
    ) -> Dict[str, Any]:
        """Track active session corresponding to issued JWT token."""
        now = datetime.now(timezone.utc)
        ua_traits = parse_user_agent_details(user_agent)
        
        # Check if device is trusted
        dev = await self.collection.find_one({"user_id": user_id, "fingerprint_hash": fingerprint_hash})
        is_trusted = dev.get("is_trusted", False) if dev else False
        risk_level = evaluate_session_risk(ip_address, is_trusted, False)
        location = "Local / Dev Session" if ip_address in ("127.0.0.1", "::1") else "Detected Network"

        session_data = {
            "user_id": user_id,
            "token_id": token_id,
            "fingerprint_hash": fingerprint_hash,
            "device_name": ua_traits["device_name"],
            "device_type": ua_traits["device_type"],
            "browser": ua_traits["browser"],
            "os": ua_traits["os"],
            "ip_address": ip_address,
            "location": location,
            "user_agent": user_agent,
            "is_active": True,
            "is_trusted": is_trusted,
            "risk_level": risk_level,
            "created_at": now,
            "last_activity": now
        }
        result = await self.sessions_collection.insert_one(session_data)
        session_data["_id"] = str(result.inserted_id)
        return session_data

    async def is_session_active(self, token_id: str) -> bool:
        """Check if token ID is active (not logged out or revoked)."""
        session = await self.sessions_collection.find_one({"token_id": token_id})
        return session is not None and session.get("is_active", False)

    async def revoke_session(self, token_id: str) -> bool:
        """Revoke specific active token ID (logs user out of single session)."""
        result = await self.sessions_collection.update_one(
            {"token_id": token_id},
            {"$set": {"is_active": False, "revoked_at": datetime.now(timezone.utc)}}
        )
        return result.modified_count > 0

    async def revoke_other_sessions(self, user_id: str, current_token_id: str) -> int:
        """Revoke all sessions for a user EXCEPT the current session."""
        result = await self.sessions_collection.update_many(
            {
                "user_id": user_id,
                "token_id": {"$ne": current_token_id},
                "is_active": True
            },
            {"$set": {"is_active": False, "revoked_at": datetime.now(timezone.utc)}}
        )
        return result.modified_count

    async def get_active_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """List active sessions for a user, enriched with device trust and risk evaluation."""
        cursor = self.sessions_collection.find({"user_id": user_id, "is_active": True}).sort("created_at", -1)
        sessions = await cursor.to_list(length=50)
        
        # Load user trusted devices map
        dev_cursor = self.collection.find({"user_id": user_id})
        dev_list = await dev_cursor.to_list(length=50)
        trusted_map = {d.get("fingerprint_hash"): d.get("is_trusted", False) for d in dev_list if "fingerprint_hash" in d}

        for s in sessions:
            s["_id"] = str(s["_id"])
            fp = s.get("fingerprint_hash", "")
            ua = s.get("user_agent", "")
            ip = s.get("ip_address", "127.0.0.1")
            
            # Enrich traits if missing
            traits = parse_user_agent_details(ua)
            if not s.get("browser") or s.get("browser") == "Unknown Browser":
                s["browser"] = traits["browser"]
            if not s.get("os") or s.get("os") == "Unknown OS":
                s["os"] = traits["os"]
            if not s.get("device_name"):
                s["device_name"] = traits["device_name"]
            if not s.get("device_type"):
                s["device_type"] = traits["device_type"]
                
            is_trusted = trusted_map.get(fp, s.get("is_trusted", False))
            s["is_trusted"] = is_trusted
            
            # Calculate calibrated risk level (never unassessed)
            s["risk_level"] = evaluate_session_risk(ip, is_trusted, s.get("is_suspicious", False))
            
            if not s.get("location"):
                s["location"] = "Local / Dev Session" if ip in ("127.0.0.1", "::1") else "Detected Network"
                
        return sessions

    async def get_registered_devices(self, user_id: str) -> List[Dict[str, Any]]:
        """Retrieve list of all hardware/client devices ever logged in under this user account."""
        cursor = self.collection.find({"user_id": user_id}).sort("last_used_at", -1)
        devices = await cursor.to_list(length=50)
        for d in devices:
            d["_id"] = str(d["_id"])
            traits = parse_user_agent_details(d.get("user_agent", ""))
            if not d.get("browser"):
                d["browser"] = traits["browser"]
            if not d.get("os"):
                d["os"] = traits["os"]
            if not d.get("device_type"):
                d["device_type"] = traits["device_type"]
        return devices
