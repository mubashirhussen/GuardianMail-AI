import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config.settings import settings
from app.logging.structured import setup_structured_logging
from app.database.connection import db_manager
from app.api.v1.routers import v1_router

# 1. Middlewares Imports
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.logging import RequestLoggingMiddleware
from app.middleware.exceptions import GlobalExceptionsMiddleware
from app.middleware.security import SecureHeadersMiddleware, limiter

logger = logging.getLogger(__name__)

from app.database.indexes import initialize_all_indexes

# 2. Application Lifespan Hooks
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing enterprise backend foundation engines...")
    try:
        await db_manager.connect()
        if db_manager.db is not None:
            await initialize_all_indexes(db_manager.db)
    except Exception as e:
        logger.critical(f"Critical connection startup failure: {str(e)}")
        # Allow server to boot degraded for Kubernetes health probe analysis
        
    yield
    
    # Shutdown
    logger.info("Initiating graceful shutdown procedures...")
    await db_manager.disconnect()
    logger.info("Graceful shutdown completed successfully.")

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from fastapi import status

class ContentLengthLimitMiddleware(BaseHTTPMiddleware):
    """Enforce request body size limits to prevent Denial of Service (DoS) upload exhaustion."""
    def __init__(self, app, max_content_length: int = 10 * 1024 * 1024):  # 10MB
        super().__init__(app)
        self.max_content_length = max_content_length

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method in ["POST", "PUT", "PATCH"]:
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > self.max_content_length:
                        return Response(
                            content="Payload Too Large: Maximum allowed size is 10MB.",
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
                        )
                except ValueError:
                    return Response(
                        content="Invalid Content-Length header.",
                        status_code=status.HTTP_400_BAD_REQUEST
                    )
        return await call_next(request)

# 3. Create FastAPI instance
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="GuardianMail AI Enterprise AI-Powered Security Backend APIs",
    version="1.0.0-baseline",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# 4. Mount Enterprise Middlewares (Executed in reverse order of mounting)
# Add standard CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount content length request limit middleware
app.add_middleware(ContentLengthLimitMiddleware)

# Mount security headers middleware
app.add_middleware(SecureHeadersMiddleware)

# Mount global exception catcher middleware
app.add_middleware(GlobalExceptionsMiddleware)

# Mount structured JSON request telemetry logging middleware
app.add_middleware(RequestLoggingMiddleware)

# Mount tracking correlation RequestID middleware (runs first)
app.add_middleware(RequestIDMiddleware)

# 5. Slowapi Rate Limiter Handler Configuration
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# 6. Initialize JSON logging formatter
setup_structured_logging(log_level="DEBUG" if settings.DEBUG else "INFO")

# 7. Include API V1 Router Registry
app.include_router(v1_router, prefix=settings.API_V1_STR)

@app.get("/", tags=["Framework API Foundation"])
def root_route():
    """Fallback root landing status page."""
    return {
        "status": "online",
        "project": settings.PROJECT_NAME,
        "api_v1_docs": "/docs"
    }
