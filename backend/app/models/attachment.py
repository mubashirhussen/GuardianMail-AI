from typing import Optional, Dict, Any
from app.models.base import BaseMongoModel
from pydantic import Field

class EmailAttachmentRecord(BaseMongoModel):
    """Metadata details tracking files attached to analyzed emails (Attachments Collection)."""
    
    email_id: str = Field(..., description="Foreign key reference link to the Emails document")
    filename: str
    content_type: str
    size_bytes: int
    md5_hash: Optional[str] = None
    sha256_hash: Optional[str] = None
    
    # OCR and Sandbox integration properties
    ocr_text_extracted: Optional[str] = None
    sandbox_result_verdict: Optional[str] = "clean"  # clean, suspicious, malicious
    sandbox_scan_report_url: Optional[str] = None
    
    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }
