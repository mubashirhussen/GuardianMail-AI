from typing import Dict, Any, Optional
from app.models.base import BaseMongoModel
from pydantic import Field

class EmailHeaders(BaseMongoModel):
    """Raw parsed and categorized header fields of ingested emails (EmailHeaders Collection)."""
    
    email_id: str = Field(..., description="Foreign key reference link to the Emails document")
    raw_headers: Dict[str, Any] = Field(default_factory=dict, description="Key-value dictionary mapping of raw parsed mail headers")
    received_hops: list = Field(default_factory=list, description="Parsed hop details from Received: headers list")
    spf_header: Optional[str] = None
    dkim_header: Optional[str] = None
    dmarc_header: Optional[str] = None
    
    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }
