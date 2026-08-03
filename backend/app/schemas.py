"""
Pydantic schemas for API request/response validation.
These are separate from database models for flexibility and validation.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field, HttpUrl, ConfigDict
from enum import Enum


# ======================== Enums ========================

class UserRoleEnum(str, Enum):
    """User roles for RBAC."""
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    USER = "user"
    VIEWER = "viewer"


class EmailThreatLevelEnum(str, Enum):
    """Email threat classification levels."""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"
    MALWARE = "malware"
    FRAUD = "fraud"


class ComplaintStatusEnum(str, Enum):
    """Complaint status tracking."""
    DRAFT = "draft"
    SUBMITTED = "submitted"
    ACKNOWLEDGED = "acknowledged"
    UNDER_INVESTIGATION = "under_investigation"
    CLOSED = "closed"
    REJECTED = "rejected"


# ======================== User Schemas ========================

class UserBase(BaseModel):
    """Base user schema with common fields."""
    email: EmailStr
    full_name: Optional[str] = None
    role: UserRoleEnum = UserRoleEnum.USER


class UserCreate(UserBase):
    """Schema for creating new user."""
    password: str = Field(min_length=8, description="Password must be at least 8 characters")


class UserUpdate(BaseModel):
    """Schema for updating user profile."""
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None


class UserResponse(UserBase):
    """Schema for user API response."""
    id: str = Field(alias="_id")
    created_at: datetime
    updated_at: datetime
    is_active: bool
    last_login: Optional[datetime] = None
    
    model_config = ConfigDict(populate_by_name=True)


# ======================== Authentication Schemas ========================

class TokenResponse(BaseModel):
    """Schema for authentication token response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class TokenRefreshRequest(BaseModel):
    """Schema for refreshing access token."""
    refresh_token: str


class LoginRequest(BaseModel):
    """Schema for login request."""
    email: EmailStr
    password: str


class GoogleOAuthCallbackRequest(BaseModel):
    """Schema for Google OAuth callback."""
    code: str
    state: Optional[str] = None


# ======================== Device Schemas ========================

class DeviceBase(BaseModel):
    """Base device schema."""
    device_name: str
    device_type: str  # mobile, desktop, tablet
    os: str  # iOS, Android, Windows, macOS, Linux
    browser: Optional[str] = None


class DeviceCreate(DeviceBase):
    """Schema for registering new device."""
    device_id: str
    user_agent: str


class DeviceResponse(DeviceBase):
    """Schema for device API response."""
    id: str = Field(alias="_id")
    device_id: str
    device_fingerprint: str
    is_trusted: bool
    created_at: datetime
    last_used_at: datetime
    
    model_config = ConfigDict(populate_by_name=True)


# ======================== Email Schemas ========================

class EmailSender(BaseModel):
    """Email sender information."""
    name: Optional[str] = None
    email: EmailStr
    domain: str


class EmailRecipient(BaseModel):
    """Email recipient information."""
    email: EmailStr
    type: str = "to"  # to, cc, bcc


class EmailMetadata(BaseModel):
    """Email metadata."""
    gmail_id: str
    message_id: str
    subject: str
    sender: EmailSender
    recipients: List[EmailRecipient]
    cc: Optional[List[EmailRecipient]] = None
    bcc: Optional[List[EmailRecipient]] = None
    received_at: datetime
    size_bytes: int


class EmailThreatAnalysis(BaseModel):
    """Email threat analysis results."""
    threat_level: EmailThreatLevelEnum
    confidence_score: float = Field(ge=0, le=1)
    risk_score: float = Field(ge=0, le=1)
    is_phishing: bool
    is_fraud: bool
    is_bec: bool
    is_malware: bool
    flags: List[str] = []
    explanation: str


class EmailResponse(BaseModel):
    """Schema for email API response."""
    id: str = Field(alias="_id")
    user_id: str
    metadata: EmailMetadata
    threat_analysis: Optional[EmailThreatAnalysis] = None
    is_read: bool
    is_flagged: bool
    status: str  # new, processing, analyzed, archived
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(populate_by_name=True)


class EmailListResponse(BaseModel):
    """Schema for paginated email list response."""
    items: List[EmailResponse]
    total: int
    page: int
    page_size: int
    has_more: bool


# ======================== Security Alert Schemas ========================

class SecurityAlertResponse(BaseModel):
    """Schema for security alert."""
    id: str = Field(alias="_id")
    user_id: str
    alert_type: str  # login_attempt, device_added, suspicious_activity
    severity: str  # low, medium, high, critical
    title: str
    description: str
    is_read: bool
    created_at: datetime
    
    model_config = ConfigDict(populate_by_name=True)


# ======================== Complaint Schemas ========================

class ComplaintCreate(BaseModel):
    """Schema for creating complaint."""
    email_id: str
    complaint_type: str  # phishing, fraud, spam, malware
    description: Optional[str] = None
    portal: str  # IC3, CyberTipline, FBI, Local Police


class ComplaintUpdate(BaseModel):
    """Schema for updating complaint."""
    status: ComplaintStatusEnum


class ComplaintResponse(BaseModel):
    """Schema for complaint API response."""
    id: str = Field(alias="_id")
    user_id: str
    email_id: str
    complaint_type: str
    description: Optional[str]
    status: ComplaintStatusEnum
    portal: str
    evidence_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    submitted_at: Optional[datetime] = None
    
    model_config = ConfigDict(populate_by_name=True)


# ======================== Report Schemas ========================

class ThreatReportRequest(BaseModel):
    """Schema for generating threat report."""
    email_id: str
    include_evidence: bool = True
    format: str = "pdf"  # pdf, json, csv


class ThreatReportResponse(BaseModel):
    """Schema for threat report response."""
    id: str = Field(alias="_id")
    email_id: str
    report_type: str
    format: str
    file_url: str
    created_at: datetime
    
    model_config = ConfigDict(populate_by_name=True)


# ======================== Analytics Schemas ========================

class DashboardStatsResponse(BaseModel):
    """Schema for dashboard statistics."""
    total_emails: int
    emails_analyzed: int
    threats_detected: int
    phishing_attempts: int
    fraud_attempts: int
    malware_detected: int
    security_score: float
    last_7_days_threats: int
    device_count: int
    active_sessions: int


class ThreatTrendResponse(BaseModel):
    """Schema for threat trends."""
    date: str
    threat_count: int
    threat_level: str


class AnalyticsResponse(BaseModel):
    """Schema for analytics data."""
    dashboard_stats: DashboardStatsResponse
    threat_trends: List[ThreatTrendResponse]
    top_threat_types: Dict[str, int]
    top_threat_senders: List[Dict[str, Any]]


# ======================== Error Response Schemas ========================

class ErrorDetail(BaseModel):
    """Schema for error detail."""
    field: Optional[str] = None
    message: str
    code: str


class ErrorResponse(BaseModel):
    """Schema for error API response."""
    success: bool = False
    error_code: str
    message: str
    details: Optional[List[ErrorDetail]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ======================== Pagination Schemas ========================

class PaginationParams(BaseModel):
    """Schema for pagination parameters."""
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)
    sort_by: Optional[str] = None
    sort_order: str = "desc"  # asc, desc
