"""
Email model for storing email metadata and threat analysis results.
Comprehensive email document supporting Gmail integration and threat analysis.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field


# ======================== Email Components ========================

class EmailAttachment(BaseModel):
    """Email attachment metadata."""
    filename: str
    content_type: str
    size_bytes: int
    md5_hash: Optional[str] = None
    sha256_hash: Optional[str] = None
    is_malicious: bool = False
    scan_result: Optional[str] = None
    details: Optional[str] = None


class EmailUrl(BaseModel):
    """URL found in email with security analysis."""
    url: str
    domain: str
    is_shortener: bool = False
    is_ip_address: bool = False
    is_typosquatting: bool = False
    reputation_score: float = Field(ge=0, le=1)  # 0 safe, 1 malicious
    vt_scan_result: Optional[str] = None
    urlscan_result: Optional[str] = None
    has_redirect: bool = False
    redirect_target: Optional[str] = None


class ThreatIndicator(BaseModel):
    """Individual threat indicator."""
    indicator: str
    detail: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float = Field(ge=0, le=1)
    type: str  # phishing, fraud, malware, bec, etc.


class SPFValidation(BaseModel):
    """SPF authentication validation."""
    pass_value: bool
    result: str  # pass, fail, softfail, none, temperror, permerror
    explanation: Optional[str] = None


class DKIMValidation(BaseModel):
    """DKIM authentication validation."""
    pass_value: bool
    domain: str
    result: str
    explanation: Optional[str] = None


class DMARCValidation(BaseModel):
    """DMARC authentication validation."""
    pass_value: bool
    domain: str
    result: str
    alignment: Optional[str] = None
    explanation: Optional[str] = None


class HeaderAuthStatus(BaseModel):
    """Email authentication status (SPF, DKIM, DMARC)."""
    spf: Optional[SPFValidation] = None
    dkim: Optional[DKIMValidation] = None
    dmarc: Optional[DMARCValidation] = None
    overall_authentication_pass: bool = False
    authentication_score: float = Field(ge=0, le=1)


class TimelineEvent(BaseModel):
    """Chronological event in the incident investigation timeline."""
    event: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    description: str


class RiskAnalysis(BaseModel):
    """Comprehensive risk analysis results."""
    verdict: str  # CRITICAL, HIGH, MEDIUM, LOW, SAFE
    risk_score: float = Field(ge=0, le=1)  # 0 to 1
    confidence_score: float = Field(ge=0, le=1)
    
    # Threat Classifications
    is_phishing: bool = False
    is_fraud: bool = False
    is_bec: bool = False
    is_malware: bool = False
    is_spam: bool = False
    
    indicators: List[ThreatIndicator] = []
    auth_status: Optional[HeaderAuthStatus] = None
    
    # Explanation & Recommendations
    explanation: str
    ai_explanation: Optional[str] = None
    
    # Explainable Threat Intelligence (Enhancement 3)
    positive_evidence: List[str] = []
    negative_evidence: List[str] = []
    detector_sources: List[str] = []
    confidence_level: str = "LOW"  # HIGH, MEDIUM, LOW
    
    # Incident Timeline (Enhancement 6)
    timeline: List[TimelineEvent] = []
    
    analysis_time: datetime = Field(default_factory=datetime.utcnow)
    model_version: str = "1.0.0"


class EmailRecommendation(BaseModel):
    """Recommendations for email handling."""
    action_priority: str  # HIGH, MEDIUM, LOW
    action_type: str  # block, delete, quarantine, allow, review
    suggestions: List[str] = []
    next_steps: List[str] = []
    explanation: str
    security_tips: List[str] = []


from app.models.base import BaseMongoModel, PyObjectId

class EmailRecord(BaseMongoModel):
    """Email document in MongoDB (Emails Collection)."""
    
    # User & Gmail Reference
    user_id: str
    gmail_message_id: Optional[str] = None
    gmail_thread_id: Optional[str] = None
    
    # Email Basic Info
    subject: str
    from_address: EmailStr
    from_domain: str
    from_name: Optional[str] = None
    to_address: List[EmailStr] = []
    cc: List[EmailStr] = []
    bcc: List[EmailStr] = []
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    date: datetime
    
    # Email Content
    body_plain: Optional[str] = None
    body_html: Optional[str] = None
    body_truncated: bool = False
    
    # Email Components
    attachments: List[EmailAttachment] = []
    urls: List[EmailUrl] = []
    
    # Email Properties
    size_bytes: int
    message_id: Optional[str] = None
    in_reply_to: Optional[str] = None
    references: Optional[List[str]] = None
    labels: List[str] = []  # Gmail labels
    is_read: bool = False
    is_flagged: bool = False
    is_starred: bool = False
    is_spam: bool = False
    
    # Thread Info
    thread_id: str
    reply_count: int = 0
    
    # Analysis Results
    analysis: Optional[RiskAnalysis] = None
    recommendations: Optional[EmailRecommendation] = None
    manual_verification: Optional[Dict[str, Any]] = None
    
    # Processing Status
    processing_status: str = "pending"  # pending, in_progress, completed, failed
    processing_error: Optional[str] = None
    last_scan_result: Optional[str] = None
    
    # Tracking
    analyzed_at: Optional[datetime] = None
    sync_time: datetime = Field(default_factory=datetime.utcnow)
    
    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }


class EmailAnalysisResponse(BaseModel):
    """Email analysis response for API."""
    email_id: str
    subject: str
    from_address: str
    verdict: str
    risk_score: float
    confidence_score: float
    is_phishing: bool
    is_fraud: bool
    is_malware: bool
    explanation: str
    recommendations: List[str]
    analysis: RiskAnalysis
    recommendations: EmailRecommendation
