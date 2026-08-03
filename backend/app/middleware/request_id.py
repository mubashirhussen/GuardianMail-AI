import uuid
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from contextvars import ContextVar

# ContextVar to hold Request-ID for access by logging handlers
request_id_ctx_var: ContextVar[str] = ContextVar("request_id", default="")

class RequestIDMiddleware(BaseHTTPMiddleware):
    """Starlette middleware injecting unique X-Request-ID tracking headers into requests and responses."""
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Extract X-Request-ID from client header or generate new identifier
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            request_id = str(uuid.uuid4())
            
        # Inject request ID into Starlette state context
        request.state.request_id = request_id
        
        # Set token ContextVar for access by structured logger formatter
        token = request_id_ctx_var.set(request_id)
        
        try:
            response = await call_next(request)
        finally:
            request_id_ctx_var.reset(token)
            
        # Write header to client response
        response.headers["X-Request-ID"] = request_id
        return response

def get_current_request_id() -> str:
    """Retrieve unique Correlation ID of the active request execution context."""
    return request_id_ctx_var.get()
