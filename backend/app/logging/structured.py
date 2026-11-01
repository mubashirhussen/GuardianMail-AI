import logging
import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict

class JSONFormatter(logging.Formatter):
    """Custom logging formatter that outputs logs in JSON format for enterprise observability."""
    
    def __init__(self, **kwargs):
        super().__init__()
        
    def format(self, record: logging.LogRecord) -> str:
        # Standard attributes to parse from LogRecord
        log_data: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "module": record.module,
            "filename": record.filename,
            "line_number": record.lineno,
        }
        
        # Include exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
            
        # Include extra payload attributes
        extra_attrs = ["request_id", "trace_id", "user_id", "client_ip", "path", "method", "status_code", "duration_ms"]
        for attr in extra_attrs:
            if hasattr(record, attr):
                log_data[attr] = getattr(record, attr)
                
        # Support arbitrary custom keys injected in extra dict
        # Standard extra arguments are added to record.__dict__
        # We can extract all custom attributes that are not in LogRecord default properties
        default_attrs = {
            'name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 'filename',
            'module', 'exc_info', 'exc_text', 'stack_info', 'lineno', 'funcName',
            'created', 'msecs', 'relativeCreated', 'thread', 'threadName',
            'processName', 'process', 'message'
        }
        for key, val in record.__dict__.items():
            if key not in default_attrs and key not in extra_attrs:
                log_data[key] = val
                
        return json.dumps(log_data)

def setup_structured_logging(log_level: str = "INFO") -> None:
    """Configure system-wide structured JSON logging handler."""
    root_logger = logging.getLogger()
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        
    # Setup standard console handler running our JSONFormatter
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(JSONFormatter())
    
    root_logger.addHandler(console_handler)
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # Suppress verbose third-party library logging if needed
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("motor").setLevel(logging.WARNING)
    logging.getLogger("pymongo").setLevel(logging.WARNING)
    logging.getLogger("pymongo.command").setLevel(logging.WARNING)
    logging.getLogger("pymongo.connection").setLevel(logging.WARNING)
    logging.getLogger("pymongo.serverSelection").setLevel(logging.WARNING)
    logging.getLogger("pymongo.topology").setLevel(logging.WARNING)
