"""
User model representing application users with their security and profile information.
Includes authentication, OAuth, MFA, and account management fields.
"""

from enum import Enum
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field


class UserRole(str, Enum):
    """User roles for role-based access control."""
    ADMIN = "admin"
    SOC_ANALYST = "soc_analyst"
    SECURITY_ANALYST = "security_analyst"
    USER = "user"
    VIEWER = "viewer"


class UserBase(BaseModel):
    """Base user schema with common fields."""
    email: EmailStr
    full_name: Optional[str] = None
    role: UserRole = UserRole.USER
    is_active: bool = True
    department: Optional[str] = None
    team: Optional[str] = None


class UserCreate(UserBase):
    """Schema for creating new user."""
    password: str = Field(min_length=8, description="Password must be at least 8 characters")


class UserLogin(BaseModel):
    """Schema for user login."""
    email: EmailStr
    password: str


class UserResponse(UserBase):
    """Schema for user API response."""
    id: str = Field(..., alias="_id")
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None
    is_verified: bool = False
    mfa_enabled: bool = False

    model_config = {
        "populate_by_name": True
    }


from app.models.base import BaseMongoModel, PyObjectId

class UserInDB(UserBase, BaseMongoModel):
    """User document in database."""
    hashed_password: str
    
    # OAuth Integration
    google_id: Optional[str] = None
    google_email: Optional[str] = None
    google_name: Optional[str] = None
    google_picture_url: Optional[str] = None
    
    # Gmail Integration
    gmail_access_token: Optional[str] = None
    gmail_refresh_token: Optional[str] = None
    gmail_token_expires_at: Optional[datetime] = None
    
    # Account Status
    is_verified: bool = False
    verification_token: Optional[str] = None
    verification_expires_at: Optional[datetime] = None
    
    # Security
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    
    # Session Management
    last_login: Optional[datetime] = None
    last_login_ip: Optional[str] = None
    last_login_user_agent: Optional[str] = None
    
    # Account Lockout
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    
    # Settings & Preferences
    email_notifications_enabled: bool = True
    threat_alerts_enabled: bool = True
    digest_frequency: str = "daily"  # daily, weekly, never
    
    last_activity_at: Optional[datetime] = None
    
    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True,
        "json_schema_extra": {
            "example": {
                "email": "user@example.com",
                "full_name": "John Doe",
                "role": "user",
                "is_active": True,
                "mfa_enabled": False
            }
        }
    }

