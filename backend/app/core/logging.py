import logging
from app.logging.structured import setup_structured_logging

def setup_logging() -> None:
    """Redirect to unified structured logging setup."""
    setup_structured_logging("INFO")
