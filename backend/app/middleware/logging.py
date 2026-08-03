import time
import logging
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from app.middleware.request_id import get_current_request_id

logger = logging.getLogger("guardianmail.api")

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Structured middleware logging request/response metrics in standardized JSON telemetry formats."""
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start_time = time.perf_counter()
        
        # Parse basic request telemetry details
        method = request.method
        path = request.url.path
        client_ip = request.client.host if request.client else "127.0.0.1"
        request_id = get_current_request_id()
        
        # Proceed with execution
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as e:
            # Let the exceptions handler handle it, but log here too
            status_code = 500
            elapsed = int((time.perf_counter() - start_time) * 1000)
            logger.error(
                f"Request execution failed: {method} {path} - Error: {str(e)}",
                extra={
                    "request_id": request_id,
                    "method": method,
                    "path": path,
                    "client_ip": client_ip,
                    "status_code": status_code,
                    "duration_ms": elapsed
                }
            )
            raise e
            
        elapsed = int((time.perf_counter() - start_time) * 1000)
        
        # Structured logger context details
        logger.info(
            f"API Request: {method} {path} completed with status {status_code} in {elapsed}ms",
            extra={
                "request_id": request_id,
                "method": method,
                "path": path,
                "client_ip": client_ip,
                "status_code": status_code,
                "duration_ms": elapsed
            }
        )
        
        return response
