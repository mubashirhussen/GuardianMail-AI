import pytest
from datetime import datetime, timezone
from fastapi import status
from httpx import AsyncClient
from app.services.email_parser import EmailParserService
from app.workers.tasks import reprocess_email_task

@pytest.mark.asyncio
async def test_email_parser_mime_and_sanitization():
    """Test MIME parser and HTML/Bleach sanitization components directly."""
    # 1. HTML tag sanitization with scripts, pixels, and allowed elements
    dirty_html = (
        "<html><body>"
        "<h1>Welcome</h1>"
        "<script>alert('dangerous');</script>"
        "<img src='pixel.gif' width='1' height='1' />"
        "<img src='normal.png' width='400' height='300' />"
        "<a href='http://legit.com'>Legit Link</a>"
        "</body></html>"
    )
    
    cleaned = EmailParserService.sanitize_html(dirty_html)
    # script block and tracking pixel decomps
    assert "dangerous" not in cleaned
    assert "script" not in cleaned
    assert "pixel.gif" not in cleaned
    # Legit elements remain
    assert "Welcome" in cleaned
    assert "normal.png" in cleaned
    assert "href=\"http://legit.com\"" in cleaned

@pytest.mark.asyncio
async def test_email_parser_link_extraction():
    """Test deep link extraction categorizations and query arguments splitting."""
    plain = "Check ftp://myftp.com/files and www.domain.com/path?arg=123#sec"
    html = "<a href='https://sub.secure-url.net/info?u=user&active=true'>Sec Link</a>"
    
    urls = EmailParserService.extract_links(plain, html)
    assert len(urls) == 3
    
    # Check ftp scheme URL
    ftp_link = next(u for u in urls if u["category"] == "FTP")
    assert ftp_link["domain"] == "myftp.com"
    assert ftp_link["path"] == "/files"
    
    # Check query params splitting
    qs_link = next(u for u in urls if u["category"] == "HTTPS")
    assert qs_link["domain"] == "sub.secure-url.net"
    assert qs_link["subdomain"] == "sub"
    assert qs_link["tld"] == "net"
    assert qs_link["query_params"]["u"] == ["user"]
    assert qs_link["query_params"]["active"] == ["true"]

@pytest.mark.asyncio
async def test_parser_api_process_and_reprocess_flows(client: AsyncClient):
    """Test REST API endpoint process, status, metadata, and background reprocess triggers."""
    # 1. Register & login
    register_payload = {
        "email": "parser_user@example.com",
        "full_name": "Parser User",
        "role": "user",
        "password": "secure_password_123"
    }
    await client.post("/api/v1/auth/register", json=register_payload)
    login_resp = await client.post("/api/v1/auth/login", json={"email": "parser_user@example.com", "password": "secure_password_123"})
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. POST /parser/process directly with hex EML payload
    raw_eml = (
        b"Subject: Sandbox Reprocess Test\r\n"
        b"From: sender@domain.com\r\n"
        b"To: parser_user@example.com\r\n\r\n"
        b"Body content referencing www.url.com/index.html"
    )
    raw_hex = raw_eml.hex()
    
    proc_resp = await client.post("/api/v1/parser/process", json={"raw_hex": raw_hex}, headers=headers)
    assert proc_resp.status_code == status.HTTP_200_OK
    data = proc_resp.json()
    assert data["subject"] == "Sandbox Reprocess Test"
    assert data["from_address"] == "sender@domain.com"
    assert len(data["urls"]) == 1
    
    # 3. Create dummy EmailRecord in database to test status and reprocess endpoints
    from app.database.connection import db_manager
    from app.repositories.email_repo import EmailRepository
    
    email_repo = EmailRepository(db_manager.db)
    
    # Simulate first sync connection setup
    await client.post("/api/v1/gmail/connect", json={"code": "oauth_auth_code_123"}, headers=headers)
    
    me_resp = await client.get("/api/v1/auth/me", headers=headers)
    user_id = me_resp.json()["_id"]
    
    email_doc = {
        "user_id": user_id,
        "gmail_message_id": "mock_gmail_msg_123",
        "gmail_thread_id": "mock_thread_123",
        "subject": "Old Subject",
        "from_address": "old@domain.com",
        "body_plain": "Old body content",
        "processing_status": "completed"
    }
    created = await email_repo.create(email_doc)
    email_id = str(created["_id"])
    
    # GET status
    status_resp = await client.get(f"/api/v1/parser/status/{email_id}", headers=headers)
    assert status_resp.status_code == status.HTTP_200_OK
    assert status_resp.json()["processing_status"] == "completed"
    
    # GET metadata
    meta_resp = await client.get(f"/api/v1/parser/metadata/{email_id}", headers=headers)
    assert meta_resp.status_code == status.HTTP_200_OK
    
    # Mock Gmail client for reprocess task
    from app.services.gmail_service import GmailService
    class MockGmailClient:
        def users(self):
             class Users:
                  def messages(self):
                       class Messages:
                            def get(self, *args, **kwargs):
                                 class GetReq:
                                      def execute(self):
                                           import base64
                                           return {"raw": base64.urlsafe_b64encode(raw_eml).decode()}
                                 return GetReq()
                       return Messages()
             return Users()
    GmailService.get_gmail_client = lambda user: MockGmailClient()

    # Trigger reprocess POST
    rep_resp = await client.post("/api/v1/parser/reprocess", json={"email_id": email_id}, headers=headers)
    assert rep_resp.status_code == status.HTTP_200_OK
    assert rep_resp.json()["status"] == "success"
    
    # Check database status was updated to reprocessing
    refetched = await email_repo.get(email_id)
    # Since Celery is in eager mode, it executes immediately, so status will be back to completed!
    assert refetched["processing_status"] == "completed"
    assert refetched["subject"] == "Sandbox Reprocess Test"
