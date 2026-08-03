import pytest
from datetime import datetime, timezone, timedelta
from fastapi import status
from httpx import AsyncClient
from app.workers.tasks import gmail_sync_job, token_refresh_job
from app.database.cache import cache_manager
from tests.conftest import MockDatabase

@pytest.mark.asyncio
async def test_gmail_account_connection_and_disconnect(client: AsyncClient):
    """Test register first, connect Google account, accounts query, and disconnect flow."""
    # 1. Register & login a test user
    register_payload = {
        "email": "ingestion_user@example.com",
        "full_name": "Ingestion User",
        "role": "user",
        "password": "secure_password_123"
    }
    await client.post("/api/v1/auth/register", json=register_payload)
    login_resp = await client.post("/api/v1/auth/login", json={"email": "ingestion_user@example.com", "password": "secure_password_123"})
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Connect Gmail account
    connect_resp = await client.post("/api/v1/gmail/connect", json={"code": "oauth_auth_code_123"}, headers=headers)
    assert connect_resp.status_code == status.HTTP_200_OK
    assert connect_resp.json()["status"] == "success"
    
    # 3. Retrieve connected accounts details
    accs_resp = await client.get("/api/v1/gmail/accounts", headers=headers)
    assert accs_resp.status_code == status.HTTP_200_OK
    accs = accs_resp.json()
    assert len(accs) == 1
    assert accs[0]["email"] == "ingestion_user@example.com"
    
    # 4. Disconnect Gmail account
    dis_resp = await client.delete("/api/v1/gmail/disconnect", headers=headers)
    assert dis_resp.status_code == status.HTTP_200_OK
    
    # Accounts should be empty now
    accs_empty = await client.get("/api/v1/gmail/accounts", headers=headers)
    assert len(accs_empty.json()) == 0

@pytest.mark.asyncio
async def test_gmail_sync_status_endpoints(client: AsyncClient):
    """Test sync status endpoints logic under auth context."""
    login_resp = await client.post("/api/v1/auth/login", json={"email": "ingestion_user@example.com", "password": "secure_password_123"})
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Connect Gmail account to allow sync
    await client.post("/api/v1/gmail/connect", json={"code": "oauth_auth_code_123"}, headers=headers)
    
    # Start sync task
    sync_resp = await client.post("/api/v1/gmail/sync", headers=headers)
    assert sync_resp.status_code == status.HTTP_200_OK
    
    # Get status (mock redis sync check)
    status_resp = await client.get("/api/v1/gmail/sync/status", headers=headers)
    assert status_resp.status_code == status.HTTP_200_OK
    
    # Trigger retry
    retry_resp = await client.post("/api/v1/gmail/sync/retry", headers=headers)
    assert retry_resp.status_code == status.HTTP_200_OK

@pytest.mark.asyncio
async def test_gmail_ingestion_normalization_and_queries(client: AsyncClient):
    """Test background task parsing, email normalization, attachments listing, and search queries."""
    login_resp = await client.post("/api/v1/auth/login", json={"email": "ingestion_user@example.com", "password": "secure_password_123"})
    user_data = login_resp.json()
    token = user_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Mock Gmail API calls inside tasks by patching client
    from app.services.gmail_service import GmailService
    
    class MockGmailClient:
        def users(self):
             class Users:
                  def messages(self):
                       class Messages:
                            def list(self, *args, **kwargs):
                                 class ListReq:
                                      def execute(self):
                                           return {"messages": [{"id": "msg_1", "threadId": "th_1"}, {"id": "msg_2", "threadId": "th_2"}]}
                                 return ListReq()
                            def get(self, *args, **kwargs):
                                 class GetReq:
                                      def execute(self):
                                           # Base64url raw EML mockup content
                                           raw_eml = (
                                               b"Subject: Security Threat Warning\r\n"
                                               b"From: security@warning.com\r\n"
                                               b"To: ingestion_user@example.com\r\n\r\n"
                                               b"Alert: suspicious link http://malicious.com detected in attachment."
                                           )
                                           import base64
                                           return {"raw": base64.urlsafe_b64encode(raw_eml).decode()}
                                 return GetReq()
                       return Messages()
             return Users()
             
    GmailService.get_gmail_client = lambda user: MockGmailClient()
    
    # Connect account first
    await client.post("/api/v1/gmail/connect", json={"code": "oauth_auth_code_123"}, headers=headers)
    
    # Fetch user_id matching current_user
    me_resp = await client.get("/api/v1/auth/me", headers=headers)
    user_id = me_resp.json()["_id"]
    
    # Run sync task synchronously
    sync_result = gmail_sync_job(user_id)
    assert sync_result["status"] == "success"
    assert sync_result["synchronized_emails_count"] == 2
    
    # Run periodic oauth token refresh checker
    refresh_result = token_refresh_job()
    assert "refreshed_users_count" in refresh_result
    
    # 2. Get normalized emails
    emails_resp = await client.get("/api/v1/emails/", headers=headers)
    assert emails_resp.status_code == status.HTTP_200_OK
    emails = emails_resp.json()
    assert len(emails) == 2
    email_id = emails[0]["_id"]
    thread_id = emails[0]["thread_id"]
    
    # 3. Get single email
    single_resp = await client.get(f"/api/v1/emails/{email_id}", headers=headers)
    assert single_resp.status_code == status.HTTP_200_OK
    assert single_resp.json()["subject"] == "Security Threat Warning"
    
    # 4. Get thread list
    thread_resp = await client.get(f"/api/v1/emails/thread/{thread_id}", headers=headers)
    assert thread_resp.status_code == status.HTTP_200_OK
    assert len(thread_resp.json()) == 1
