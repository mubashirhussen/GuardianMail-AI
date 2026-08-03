import logging
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from app.exceptions.custom import GuardianMailException
from app.middleware.request_id import get_current_request_id

logger = logging.getLogger("guardianmail.exceptions")

class GlobalExceptionsMiddleware(BaseHTTPMiddleware):
    """Centralized middleware catching all exceptions during execution and returning consistent JSON payloads."""
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        try:
            return await call_next(request)
        except Exception as exc:
            return self.handle_exception(exc)

    def handle_exception(self, exc: Exception) -> JSONResponse:
        request_id = get_current_request_id()
        
        # 1. Custom Business exceptions
        if isinstance(exc, GuardianMailException):
            logger.error(
                f"Business Exception [{exc.__class__.__name__}]: {exc.message}",
                extra={"request_id": request_id, "status_code": exc.status_code}
            )
            return JSONResponse(
                status_code=exc.status_code,
                content={
                    "success": False,
                    "code": exc.__class__.__name__.upper(),
                    "message": exc.message,
                    "details": exc.details,
                    "request_id": request_id
                }
            )

        # 2. FastAPI Request validation errors
        if isinstance(exc, RequestValidationError):
            logger.warning(
                f"Validation Exception: {str(exc)}",
                extra={"request_id": request_id, "status_code": 422}
            )
            return JSONResponse(
                status_code=422,
                content={
                    "success": False,
                    "code": "VALIDATION_ERROR",
                    "message": "Invalid request fields validation failed.",
                    "details": exc.errors(),
                    "request_id": request_id
                }
            )

        # 3. Standard FastAPI/Starlette HTTP exceptions
        if isinstance(exc, StarletteHTTPException):
            logger.warning(
                f"HTTP Exception: {exc.detail}",
                extra={"request_id": request_id, "status_code": exc.status_code}
            )
            return JSONResponse(
                status_code=exc.status_code,
                content={
                    "success": False,
                    "code": "HTTP_ERROR",
                    "message": exc.detail,
                    "details": {},
                    "request_id": request_id
                }
            )

        # 4. Fallback: Unexpected Server errors
        logger.exception(
            f"Unhandled exception encountered: {str(exc)}",
            extra={"request_id": request_id, "status_code": 500}
        )
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred on the server.",
                "details": {},
                "request_id": request_id
            }
        )
