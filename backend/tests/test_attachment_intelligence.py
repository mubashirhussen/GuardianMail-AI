import pytest
from httpx import AsyncClient
from app.services.attachment_analyzer import AttachmentAnalyzerService
from app.workers.tasks import analyze_attachment_task, ocr_task, qr_task
from app.database.connection import db_manager
from bson import ObjectId

@pytest.mark.asyncio
async def test_attachment_ingestion_and_metadata():
    """Verify that file ingestion parses metadata and hashes correctly."""
    # Test text file parsing
    text_data = b"Hello, this is a plain text file containing some information."
    res = await AttachmentAnalyzerService.analyze_attachment(text_data, "test.txt")
    
    assert res["filename"] == "test.txt"
    assert res["extension"] == ".txt"
    assert res["size_bytes"] == len(text_data)
    assert "sha256" in res
    assert "md5" in res
    assert res["entropy"] > 0.0
    assert "plain" in res["mime_type"] or "octet-stream" in res["mime_type"]
    assert res["word_count"] > 0
    assert res["doc_category"] == "DOCUMENT"

@pytest.mark.asyncio
async def test_document_classification():
    """Verify document category classification based on textual heuristics."""
    invoice_text = "INVOICE #1024\nBill To: John Doe\nAmount Due: $150.00\nTotal Tax: $10.00"
    cat = AttachmentAnalyzerService.classify_document(invoice_text)
    assert cat == "INVOICE"
    
    resume_text = "Curriculum Vitae\nExperience: Senior Software Engineer\nEducation: Bachelor of Computer Science\nSkills: Python, Go"
    cat = AttachmentAnalyzerService.classify_document(resume_text)
    assert cat == "RESUME"
    
    id_text = "National Identity Card\nPassport Number: ABC123456\nDate of Birth: 1990-01-01"
    cat = AttachmentAnalyzerService.classify_document(id_text)
    assert cat == "IDENTITY_DOCUMENT"

@pytest.mark.asyncio
async def test_qr_payload_classification():
    """Verify QR code payload categories and reputation classification."""
    # URL classification
    qr_url = AttachmentAnalyzerService._parse_qr_payload("https://g00gle.com/login")
    assert qr_url["category"] == "URL"
    assert qr_url["domain"] == "g00gle.com"
    assert qr_url["suspicious"] is True
    assert qr_url["reputation"] == "MALICIOUS"

    # Tel URI
    qr_tel = AttachmentAnalyzerService._parse_qr_payload("tel:+123456789")
    assert qr_tel["category"] == "PHONE"

    # WiFi configuration URI
    qr_wifi = AttachmentAnalyzerService._parse_qr_payload("WIFI:T:WPA;S:MyNetwork;P:MyPassword;;")
    assert qr_wifi["category"] == "WIFI"

    # Payment URI
    qr_pay = AttachmentAnalyzerService._parse_qr_payload("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=0.01")
    assert qr_pay["category"] == "PAYMENT"

@pytest.mark.asyncio
async def test_visual_phishing_detection():
    """Verify visual threat detection and impersonation warning alerts."""
    # Test credential lure match
    res = await AttachmentAnalyzerService.analyze_attachment(
        b"Microsoft Outlook login page. Enter your password and username to sign in.",
        "attachment.png"
    )
    assert res["visual_phishing_detected"] is True
    assert res["visual_confidence"] >= 0.7
    assert any("Credential Collection" in ind for ind in res["visual_indicators"])
    assert any("Outlook" in ind for ind in res["visual_indicators"])

@pytest.mark.asyncio
async def test_file_structure_obfuscation():
    """Verify detection of double extensions, password protection, and macros."""
    # Double extension check
    res = await AttachmentAnalyzerService.analyze_attachment(b"mock data", "document.pdf.exe")
    assert res["risk_indicators"][0] == "Double extension masquerade threat: 'document.pdf.exe'"
    assert "Executable file payload detected." in res["risk_indicators"]

    # Macro triggers check inside docx bytes (by passing office macro file format extension)
    res_macro = await AttachmentAnalyzerService.analyze_attachment(b"mock office file with VBA_Project inside", "sheet.xlsm")
    assert res_macro["has_macros"] is True
    assert "Embedded VBA/Macro scripting signature present." in res_macro["risk_indicators"]

@pytest.mark.asyncio
async def test_celery_jobs_execution():
    """Verify Celery task workflows in eager execution mode."""
    # Verify ocr_task wrapper
    ocr_result = ocr_task.delay("89504e470d0a1a0a").get()  # PNG headers hex representation
    assert "text" in ocr_result
    
    # Verify qr_task wrapper
    qr_result = qr_task.delay("89504e470d0a1a0a").get()
    assert "urls" in qr_result

    # Verify analyze_attachment_task
    # Inject a mock attachment record in MongoDB first
    doc = {
        "filename": "async_test.txt",
        "content_bytes": b"Async background processing content.",
        "status": "pending"
    }
    insert_res = await db_manager.db["attachments"].insert_one(doc)
    doc_id = str(insert_res.inserted_id)

    task_res = analyze_attachment_task.delay(doc_id).get()
    assert task_res["status"] == "success"
    assert task_res["attachment_id"] == doc_id

    # Check updated record in DB
    updated = await db_manager.db["attachments"].find_one({"_id": ObjectId(doc_id)})
    assert updated["status"] == "completed"
    assert updated["analysis"]["filename"] == "async_test.txt"
    assert updated["analysis"]["word_count"] == 4
