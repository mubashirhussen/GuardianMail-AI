import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database.connection import db_manager
from app.repositories.device_repo import DeviceRepository, parse_user_agent_details, evaluate_session_risk

def test_parse_user_agent_details():
    """Verify user agent strings are correctly mapped to human-friendly device descriptions."""
    win = parse_user_agent_details("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0")
    assert win["os"] == "Windows"
    assert win["browser"] == "Chrome"
    assert win["device_type"] == "desktop"
    assert "Windows Workstation" in win["device_name"]

    android = parse_user_agent_details("Mozilla/5.0 (Linux; Android 14; SM-S928B) Chrome/122.0.6261.64 Mobile Safari/537.36")
    assert android["os"] == "Android"
    assert android["browser"] == "Chrome"
    assert android["device_type"] == "mobile"
    assert "Android Mobile" in android["device_name"]

    ios = parse_user_agent_details("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Version/17.4 Mobile Safari/604.1")
    assert ios["os"] == "iOS"
    assert ios["browser"] == "Safari"
    assert ios["device_type"] == "mobile"
    assert "Apple iPhone" in ios["device_name"]

def test_evaluate_session_risk():
    """Verify session risk evaluation never leaves devices unassessed."""
    assert evaluate_session_risk("127.0.0.1", is_trusted=False) == "LOW"
    assert evaluate_session_risk("192.168.1.5", is_trusted=False) == "LOW"
    assert evaluate_session_risk("203.0.113.45", is_trusted=True) == "LOW"
    assert evaluate_session_risk("203.0.113.45", is_trusted=False) == "MEDIUM"
    assert evaluate_session_risk("203.0.113.45", is_trusted=False, is_suspicious=True) == "HIGH"
