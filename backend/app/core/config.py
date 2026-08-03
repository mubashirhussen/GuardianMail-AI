import os
from typing import List, Optional
from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """
    Application configuration for GuardianMail AI Enterprise Platform.
    Load from environment variables and .env file.
    """
    
    # === API Configuration ===
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "GuardianMail AI"
    PROJECT_VERSION: str = "1.0.0"
    ENVIRONMENT: str = Field(default="development", pattern="^(development|staging|production)$")
    DEBUG: bool = False
    
    # === Security & JWT ===
    SECRET_KEY: str = Field(
        default="supersecret_fallback_key_for_jwt_signing_change_in_production",
        min_length=32,
        description="Secret key for JWT signing. MUST be changed in production"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # === Session & Account Security ===
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_SECONDS: int = 900  # 15 minutes
    SESSION_IDLE_TIMEOUT_SECONDS: int = 1800  # 30 minutes
    MFA_ENABLED: bool = False
    PASSWORDLESS_AUTH_ENABLED: bool = False
    
    # === CORS Configuration ===
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]
    
    # === Database Configuration ===
    MONGODB_URL: str = "mongodb://localhost:27017"
    MONGODB_DB_NAME: str = "guardianmail"
    MONGODB_POOL_SIZE: int = 10
    MONGODB_MAX_IDLE_TIME_SECONDS: int = 45
    DB_ECHO: bool = False  # Log database queries
    
    # === Redis Configuration ===
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_CACHE_EXPIRE_SECONDS: int = 3600  # 1 hour
    
    # === Celery Background Processing ===
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"
    CELERY_WORKER_CONCURRENCY: int = 4
    CELERY_TASK_SOFT_TIME_LIMIT: int = 3600  # 1 hour
    CELERY_TASK_TIME_LIMIT: int = 3700  # 1 hour + 100 seconds
    
    # === Gmail OAuth 2.0 ===
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/api/v1/auth/google/callback"
    GOOGLE_SCOPES: List[str] = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ]
    
    # === External Security APIs ===
    VIRUSTOTAL_API_KEY: Optional[str] = None
    URLSCAN_API_KEY: Optional[str] = None
    PHISHTANK_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    
    # === AI & ML Configuration ===
    GEMINI_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    USE_LOCAL_ML_MODELS: bool = True
    ML_MODEL_PATH: str = "models/"
    
    # === Email Synchronization ===
    GMAIL_SYNC_BATCH_SIZE: int = 100
    GMAIL_SYNC_INTERVAL_MINUTES: int = 5
    GMAIL_INCREMENTAL_SYNC_ENABLED: bool = True
    EMAIL_RETENTION_DAYS: int = 365
    
    # === URL Security Settings ===
    URL_REDIRECT_DETECTION_ENABLED: bool = True
    URL_TYPOSQUATTING_CHECK_ENABLED: bool = True
    URL_HOMOGRAPH_DETECTION_ENABLED: bool = True
    
    # === Threat Detection Configuration ===
    THREAT_CONFIDENCE_THRESHOLD: float = 0.7  # 70% confidence
    RISK_SCORE_THRESHOLD: float = 0.6  # 60% risk
    PHISHING_DETECTION_MODEL: str = "gradient_boosting"  # or "neural_network"
    FRAUD_DETECTION_ENABLED: bool = True
    BEC_DETECTION_ENABLED: bool = True
    
    # === File & Attachment Analysis ===
    MAX_ATTACHMENT_SIZE_MB: int = 100
    ALLOWED_FILE_TYPES: List[str] = [
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "txt", "csv", "jpg", "jpeg", "png", "gif"
    ]
    MALWARE_SCAN_ENABLED: bool = True
    MACRO_DETECTION_ENABLED: bool = True
    
    # === OCR Configuration ===
    OCR_ENABLED: bool = True
    OCR_LANGUAGE: str = "eng"
    OCR_TIMEOUT_SECONDS: int = 60
    
    # === Notification Settings ===
    EMAIL_NOTIFICATIONS_ENABLED: bool = True
    PUSH_NOTIFICATIONS_ENABLED: bool = False
    SMS_NOTIFICATIONS_ENABLED: bool = False
    NOTIFICATION_BATCH_SIZE: int = 100
    NOTIFICATION_BATCH_INTERVAL_SECONDS: int = 60
    
    # === Audit & Logging ===
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # json or text
    AUDIT_LOG_RETENTION_DAYS: int = 365
    ENABLE_STRUCTURED_LOGGING: bool = True
    
    # === Rate Limiting ===
    RATE_LIMIT_PER_MINUTE: int = 1000
    RATE_LIMIT_PER_HOUR: int = 50000
    
    # === Monitoring & Observability ===
    PROMETHEUS_ENABLED: bool = True
    PROMETHEUS_PORT: int = 8001
    ENABLE_PERFORMANCE_MONITORING: bool = True
    SLOW_QUERY_THRESHOLD_MS: int = 1000
    
    # === Pagination & API Limits ===
    DEFAULT_PAGE_SIZE: int = 20
    MAX_PAGE_SIZE: int = 100
    
    # === Security Headers ===
    ENABLE_SECURITY_HEADERS: bool = True
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="allow"
    )

# Initialize settings
settings = Settings()
