from typing import Any
from app.models.base import BaseMongoModel
from pydantic import Field

class SystemConfiguration(BaseMongoModel):
    """Dynamic operational parameters adjustable on runtime (SystemConfigurations Collection)."""
    
    config_key: str = Field(..., description="Unique settings string lookup name")
    config_value: Any = Field(..., description="Value associated with system parameter")
    description: str
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
