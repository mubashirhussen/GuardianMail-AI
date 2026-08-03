from typing import Optional, List
from app.models.base import BaseMongoModel
from pydantic import Field

class EvidencePack(BaseMongoModel):
    """Bundled binary/text data packages representing logs and headers exported for portals (EvidencePacks Collection)."""
    
    email_id: str = Field(..., description="Foreign key reference link to the Emails document")
    pack_name: str
    export_format: str  # text, json, csv, zip
    content_payload: str = Field(..., description="Encoded string representation of evidence zip or report content")
    file_size_bytes: int
    download_url: Optional[str] = None
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
