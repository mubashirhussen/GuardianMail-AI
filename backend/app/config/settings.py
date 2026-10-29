import os
from typing import List, Optional, Any
from pydantic import AnyHttpUrl, field_validator, model_validator
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
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours persistent active session
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_SECONDS: int = 900  # 15 minutes
    
    # External Threat Intelligence & Security APIs
    VIRUSTOTAL_API_KEY: Optional[str] = None
    SAFE_BROWSING_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    URLSCAN_API_KEY: Optional[str] = None
    PHISHTANK_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    
    # AI & LLM Cognitive Analysis Engines
    AI_PROVIDER: str = "gemini"
    GEMINI_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4-turbo"
    
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
    
    # Identity Verification & Multi-Channel Delivery
    AUTH_CODE_TTL_SECONDS: int = 600
    AUTH_RESEND_COOLDOWN_SECONDS: int = 60
    AUTH_MAX_VERIFICATION_ATTEMPTS: int = 5
    FRONTEND_URL: str = "http://localhost:5173"
    BACKEND_URL: str = "http://localhost:8000"
    
    # Transactional Email Provider (console, smtp, resend, sendgrid)
    EMAIL_PROVIDER: str = "console"
    EMAIL_API_KEY: Optional[str] = None
    EMAIL_FROM_ADDRESS: str = "security@guardianmail.ai"
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_USE_TLS: bool = True
    
    # SMS Verification Provider (console, twilio, twilio_verify)
    SMS_PROVIDER: str = "console"
    TWILIO_ACCOUNT_SID: Optional[str] = None
    TWILIO_AUTH_TOKEN: Optional[str] = None
    TWILIO_VERIFY_SERVICE_SID: Optional[str] = None
    TWILIO_FROM_NUMBER: Optional[str] = None
    
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    @field_validator("CORS_ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Any) -> Any:
        if isinstance(v, str):
            v_stripped = v.strip()
            if not v_stripped.startswith("["):
                return [i.strip() for i in v_stripped.split(",") if i.strip()]
        return v

    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = ["development", "testing", "production"]
        if v.lower() not in allowed:
            raise ValueError(f"ENVIRONMENT must be one of {allowed}")
        return v.lower()

    @model_validator(mode="after")
    def validate_production_config(self) -> "Settings":
        if self.ENVIRONMENT == "production":
            # Validate JWT secret key strength
            if (
                not self.SECRET_KEY
                or "default" in self.SECRET_KEY.lower()
                or "change-me" in self.SECRET_KEY.lower()
                or "production-ready" in self.SECRET_KEY.lower()
                or len(self.SECRET_KEY) < 32
            ):
                raise ValueError("SECRET_KEY must be a cryptographically strong, non-default string of at least 32 characters in production.")
            
            # Validate OAuth secrets presence
            if not self.GOOGLE_CLIENT_ID or not self.GOOGLE_CLIENT_SECRET:
                raise ValueError("Google OAuth credentials (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET) must be set in production.")
            
            # Prevent wildcard CORS rules
            if "*" in self.CORS_ALLOWED_ORIGINS:
                raise ValueError("Wildcard '*' CORS origins are strictly forbidden in production.")
        return self

# Instantiated settings singleton
settings = Settings()
