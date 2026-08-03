import os
from typing import List, Optional
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """System-wide configuration settings with validation using Pydantic Settings v2."""
    
    # Core Environment Settings
    ENVIRONMENT: str = "development"  # development, testing, production
    DEBUG: bool = True
    PROJECT_NAME: str = "GuardianMail AI"
    API_V1_STR: str = "/api/v1"
    
    # MongoDB Atlas Connection
    MONGODB_URL: str = "mongodb://localhost:27017"
    MONGODB_DB_NAME: str = "guardianmail"
    MONGODB_POOL_SIZE: int = 20
    MONGODB_TIMEOUT_MS: int = 5000
    
    # Redis Cache & Broker Settings
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_TIMEOUT_MS: int = 2000
    
    # Security & JWT Tokens Configuration
    SECRET_KEY: str = "enterprise-default-super-secure-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_SECONDS: int = 900  # 15 minutes
    
    # Rate Limiting Configurations
    RATE_LIMIT_PER_MINUTE: int = 60
    
    # CORS Allowed Origins
    CORS_ALLOWED_ORIGINS: List[str] = [
        "http://localhost",
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8000",
        "http://127.0.0.1",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8000"
    ]
    
    # Google OAuth 2.0 Client credentials
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/api/v1/auth/callback"
    
    # Celery Background Workers
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"
    
    # Observability & Metrics
    PROMETHEUS_METRICS_ENABLED: bool = True
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = ["development", "testing", "production"]
        if v.lower() not in allowed:
            raise ValueError(f"ENVIRONMENT must be one of {allowed}")
        return v.lower()

# Instantiated settings singleton
settings = Settings()
