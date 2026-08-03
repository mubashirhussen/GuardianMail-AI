import pytest
from fastapi import status
from httpx import AsyncClient
from app.services.attachment_analyzer import AttachmentAnalyzerService

@pytest.mark.asyncio
async def test_attachment_entropy_and_double_extensions():
    """Verify entropy formulas, double extension detection, and macro triggers."""
    # 1. Zero bytes data entropy
    assert AttachmentAnalyzerService.calculate_entropy(b"") == 0.0
    
    # 2. Executable masquerade double extension check
    analysis = await AttachmentAnalyzerService.analyze_attachment(b"mock_exe_bytes", "invoice.pdf.exe")
    assert "Double extension" in analysis["risk_indicators"][0]
    assert analysis["doc_category"] == "DOCUMENT"
    assert analysis["extension"] == ".exe"
    
    # 3. Macro script triggers check
    macro_data = b"Some random content with VBA_Project signature details"
    m_analysis = await AttachmentAnalyzerService.analyze_attachment(macro_data, "sheet.xlsm")
    assert m_analysis["has_macros"] is True
    assert "Macro" in m_analysis["risk_indicators"][0]

@pytest.mark.asyncio
async def test_attachments_api_endpoints_workflow(client: AsyncClient):
    """Verify REST endpoints for files upload, OCR query, QR parsing, and report summaries."""
    # 1. Register & login
    register_payload = {
        "email": "attach_user@example.com",
        "full_name": "Attach User",
        "role": "user",
        "password": "secure_password_123"
    }
    await client.post("/api/v1/auth/register", json=register_payload)
    login_resp = await client.post("/api/v1/auth/login", json={"email": "attach_user@example.com", "password": "secure_password_123"})
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Prepare file binary payload
    file_payload = {"file": ("suspicious_invoice.png", b"fake_png_data_bytes", "image/png")}

    # A. POST /attachments/analyze
    an_resp = await client.post("/api/v1/attachments/analyze", files=file_payload, headers=headers)
    assert an_resp.status_code == status.HTTP_200_OK
    data = an_resp.json()
    assert "entropy" in data
    assert "sha256" in data
    attachment_id = data["id"]
    
    # B. POST /attachments/ocr
    ocr_resp = await client.post("/api/v1/attachments/ocr", files=file_payload, headers=headers)
    assert ocr_resp.status_code == status.HTTP_200_OK
    assert "text" in ocr_resp.json()
    
    # C. POST /attachments/qr
    qr_resp = await client.post("/api/v1/attachments/qr", files=file_payload, headers=headers)
    assert qr_resp.status_code == status.HTTP_200_OK
    assert "urls" in qr_resp.json()
    
    # D. GET /attachments/{id}
    get_resp = await client.get(f"/api/v1/attachments/{attachment_id}", headers=headers)
    assert get_resp.status_code == status.HTTP_200_OK
    assert get_resp.json()["id"] == attachment_id
    
    # E. GET /attachments/report/{id}
    rep_resp = await client.get(f"/api/v1/attachments/report/{attachment_id}", headers=headers)
    assert rep_resp.status_code == status.HTTP_200_OK
    assert rep_resp.json()["attachment_id"] == attachment_id
