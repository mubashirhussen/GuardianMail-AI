import pytest
import io
import json
import zipfile
from datetime import datetime, timezone
from httpx import AsyncClient
from app.database.connection import db_manager
from app.workers.tasks import precompute_dashboard_metrics_task, refresh_analytics_cache_task

@pytest.mark.asyncio
async def test_dashboard_analytics_workflow(client: AsyncClient):
    # 1. Register and login standard user and admin user
    # Standard user
    await client.post("/api/v1/auth/register", json={
        "email": "user@example.com",
        "username": "user",
        "password": "secure_password_123",
        "full_name": "Standard User",
        "role": "user"
    })
    user_login = await client.post("/api/v1/auth/login", json={
        "email": "user@example.com",
        "password": "secure_password_123"
    })
    user_token = user_login.json()["access_token"]
    user_headers = {"Authorization": f"Bearer {user_token}"}

    # Admin user
    await client.post("/api/v1/auth/register", json={
        "email": "admin@example.com",
        "username": "admin",
        "password": "secure_admin_password_123",
        "full_name": "Admin User",
        "role": "admin"
    })
    admin_login = await client.post("/api/v1/auth/login", json={
        "email": "admin@example.com",
        "password": "secure_admin_password_123"
    })
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 2. Inject mock emails and incidents
    user_record = await db_manager.db["users"].find_one({"email": "user@example.com"})
    user_id_str = str(user_record["_id"])

    mock_email = {
        "user_id": user_id_str,
        "subject": "Phishing Alert",
        "from_address": "phish@paypal-spoof.com",
        "sender_domain": "paypal-spoof.com",
        "date": "2026-07-29T12:00:00Z",
        "soft_delete": False,
        "gmail_account": "user@example.com",
        "attachments": [{"filename": "invoice.pdf", "content_type": "application/pdf", "size_bytes": 5000, "is_malicious": True}],
        "urls": [{"url": "http://paypal-spoof.com/reset", "domain": "paypal-spoof.com", "reputation_score": 0.95, "is_shortener": False, "has_redirect": False}],
        "analysis": {
            "verdict": "PHISHING",
            "risk_score": 0.85,
            "confidence_score": 0.90,
            "is_phishing": True,
            "is_spam": False,
            "is_bec": False,
            "indicators": [{"indicator": "Phish URL", "detail": "High risk", "severity": "HIGH", "confidence": 0.95, "type": "phishing"}]
        }
    }
    await db_manager.db["emails"].insert_one(mock_email)

    mock_incident = {
        "incident_id": "INC-2026-TESTDASH",
        "status": "Detected",
        "threat_severity": "CRITICAL",
        "detection_time": datetime.now(timezone.utc),
        "threat_category": "PHISHING",
        "confidence": 0.90,
        "affected_user": user_id_str,
        "affected_email": "mock_id_placeholder",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "soft_delete": False
    }
    await db_manager.db["incidents"].insert_one(mock_incident)

    # 3. Test Dashboard Overview
    overview_resp = await client.get("/api/v1/dashboard/overview", headers=user_headers)
    assert overview_resp.status_code == 200
    ov_data = overview_resp.json()
    assert ov_data["total_emails"] >= 1
    assert ov_data["phishing_emails"] >= 1
    assert ov_data["open_incidents"] >= 1

    # 4. Test Threats Analytics
    threats_resp = await client.get("/api/v1/dashboard/threats", headers=user_headers)
    assert threats_resp.status_code == 200
    threats_data = threats_resp.json()
    assert "PHISHING" in threats_data["severity_distribution"]
    assert threats_data["average_detection_confidence"] > 0

    # 5. Test Email Analytics
    emails_resp = await client.get("/api/v1/dashboard/emails", headers=user_headers)
    assert emails_resp.status_code == 200
    emails_data = emails_resp.json()
    assert "phish@paypal-spoof.com" in emails_data["emails_by_sender"]
    assert "paypal-spoof.com" in emails_data["emails_by_domain"]
    assert emails_data["attachment_stats"]["malicious_count"] >= 1

    # 6. Test URL/Sender Analytics
    analytics_resp = await client.get("/api/v1/dashboard/analytics", headers=user_headers)
    assert analytics_resp.status_code == 200
    an_data = analytics_resp.json()
    assert len(an_data["url_analytics"]["top_malicious_domains"]) >= 1

    # 7. Test Incident Analytics
    incidents_resp = await client.get("/api/v1/dashboard/incidents", headers=user_headers)
    assert incidents_resp.status_code == 200
    inc_data = incidents_resp.json()
    assert inc_data["status_distribution"].get("Detected", 0) >= 1

    # 8. Test Trends
    trends_resp = await client.get("/api/v1/dashboard/trends", headers=user_headers)
    assert trends_resp.status_code == 200
    trends_data = trends_resp.json()
    assert len(trends_data["daily_scans_trend"]) >= 1

    # 9. Test Users Security Analytics
    users_resp = await client.get("/api/v1/dashboard/users", headers=user_headers)
    assert users_resp.status_code == 200
    users_data = users_resp.json()
    assert users_data["total_incidents"] >= 1

    # 10. Test System Health Dashboard (Admin only, user gets 403)
    sys_user_resp = await client.get("/api/v1/dashboard/system", headers=user_headers)
    assert sys_user_resp.status_code == 403

    sys_admin_resp = await client.get("/api/v1/dashboard/system", headers=admin_headers)
    assert sys_admin_resp.status_code == 200
    assert sys_admin_resp.json()["mongodb"] == "healthy"

    # 11. Test Admin Dashboard (Admin only, user gets 403)
    admin_user_resp = await client.get("/api/v1/dashboard/admin", headers=user_headers)
    assert admin_user_resp.status_code == 403

    admin_admin_resp = await client.get("/api/v1/dashboard/admin", headers=admin_headers)
    assert admin_admin_resp.status_code == 200
    assert admin_admin_resp.json()["total_users"] >= 2

    # 12. Test Reporting and Export Engine (Post /export)
    # PDF Format
    pdf_resp = await client.post("/api/v1/dashboard/export?report_type=executive_summary&export_format=pdf", headers=user_headers)
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert len(pdf_resp.content) > 0

    # Excel Format
    excel_resp = await client.post("/api/v1/dashboard/export?report_type=threat_report&export_format=xlsx", headers=user_headers)
    assert excel_resp.status_code == 200
    assert excel_resp.headers["content-type"] == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    assert len(excel_resp.content) > 0

    # CSV Format
    csv_resp = await client.post("/api/v1/dashboard/export?report_type=threat_report&export_format=csv", headers=user_headers)
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    assert len(csv_resp.content) > 0

    # ZIP Format
    zip_resp = await client.post("/api/v1/dashboard/export?report_type=executive_summary&export_format=zip", headers=user_headers)
    assert zip_resp.status_code == 200
    assert zip_resp.headers["content-type"] == "application/zip"
    
    # Inspect ZIP structure
    zip_buf = io.BytesIO(zip_resp.content)
    with zipfile.ZipFile(zip_buf) as z:
        namelist = z.namelist()
        assert "report.pdf" in namelist
        assert "report.csv" in namelist
        assert "report.xlsx" in namelist
        assert "report.json" in namelist

    # 13. Test Paginated Reports history list
    list_reports_resp = await client.get("/api/v1/dashboard/reports?skip=0&limit=10", headers=user_headers)
    assert list_reports_resp.status_code == 200
    reports_list = list_reports_resp.json()
    assert len(reports_list) >= 4  # generated 4 reports during this test context!

@pytest.mark.asyncio
async def test_dashboard_celery_background_jobs():
    # Test Celery precompute and cache tasks in eager execution mode
    precompute_res = precompute_dashboard_metrics_task.delay("user@example.com").get()
    assert precompute_res["status"] == "success"
    assert precompute_res["user_id"] == "user@example.com"

    refresh_res = refresh_analytics_cache_task.delay().get()
    assert refresh_res["status"] == "success"
    assert refresh_res["refreshed"] is True
