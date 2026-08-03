from datetime import datetime
from typing import Optional, List
from app.models.base import BaseMongoModel, PyObjectId
from pydantic import BaseModel, Field

class DeviceLoginHistory(BaseModel):
    """Sub-document tracking individual login details for a trusted device."""
    login_time: datetime
    ip_address: str
    user_agent: str
    success: bool = True
    failure_reason: Optional[str] = None

class UserDevice(BaseMongoModel):
    """Registered user device model containing fingerprint hashes and trust status (Devices Collection)."""
    
    user_id: str
    device_id: str = Field(..., description="Unique client identifier generated or read on device")
    fingerprint_hash: str = Field(..., description="SHA256 hash representing device hardware traits")
    device_name: str
    device_type: str  # desktop, mobile, tablet
    os: str  # Windows, macOS, Linux, iOS, Android
    browser: Optional[str] = None
    user_agent: str
    last_login_ip: str
    is_trusted: bool = False
    trust_date: Optional[datetime] = None
    is_blocked: bool = False
    
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    has_biometric_auth: bool = False
    
    login_history: List[DeviceLoginHistory] = Field(default_factory=list)
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
