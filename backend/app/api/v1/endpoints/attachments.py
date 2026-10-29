from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Query
from bson import ObjectId
from app.api.dependencies.auth import get_current_active_user
from app.models.user import UserInDB
from app.database.connection import db_manager
from app.services.attachment_analyzer import AttachmentAnalyzerService
from app.telemetry.otel import trace_span

import os
import re

ALLOWED_EXTENSIONS = {
    # Documents
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf",
    # Images
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "tiff", "svg", "ico",
    # Text, Code & Data
    "txt", "csv", "json", "xml", "html", "htm", "md", "log", "yaml", "yml", "sql", "py", "js", "ts",
    # Archives & Compressed
    "zip", "rar", "7z", "tar", "gz", "bz2",
    # Emails & Communication
    "eml", "msg",
    # Executables & Binaries (Supported for malware analysis)
    "exe", "dll", "bin", "iso", "apk", "jar", "bat", "cmd", "vbs", "ps1", "scr"
}

def sanitize_and_validate_filename(filename: str) -> str:
    """Sanitize the uploaded file name to prevent path traversal while accepting any file format."""
    if not filename:
        return "unnamed_attachment.bin"
        
    # Prevent Path Traversal (e.g. ../../../etc/passwd)
    clean_base = os.path.basename(filename)
    
    # Restrict to safe character-sets while preserving spaces, dots, dashes
    sanitized = re.sub(r'[^a-zA-Z0-9._\s-]', '', clean_base).strip()
    if not sanitized:
        sanitized = "attachment_file"
        
    return sanitized

router = APIRouter()

@router.get("/")
async def list_user_attachments(
    skip: int = 0,
    limit: int = 50,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """List recent attachment scans for the authenticated user."""
    if db_manager.db is None:
        return []
    cursor = db_manager.db["attachments"].find(
        {"user_id": str(current_user.id)}
    ).sort("created_at", -1).skip(skip).limit(limit)
    docs = await cursor.to_list(length=limit)
    results = []
    for d in docs:
        item = dict(d.get("analysis", {}))
        item["id"] = str(d["_id"])
        item["attachment_id"] = str(d["_id"])
        item["filename"] = d.get("filename", item.get("filename", "unknown"))
        item["file_size_bytes"] = d.get("file_size_bytes", item.get("file_size_bytes", 0))
        item["verdict"] = d.get("verdict", item.get("verdict", "SAFE"))
        item["risk_score"] = d.get("risk_score", item.get("risk_score", 0))
        results.append(item)
    return results

@router.post("/scan")
@router.post("/analyze")
@trace_span(name="attachment_analyze")
async def analyze_attachment_file(
    file: UploadFile = File(...),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Ingest any file attachment format, parse structures, and compute security risk indices."""
    sanitized_filename = sanitize_and_validate_filename(file.filename)
    if db_manager.db is None:
          raise RuntimeError("Database connection not ready.")
          
    content = await file.read()
    analysis = await AttachmentAnalyzerService.analyze_attachment(content, sanitized_filename)
    
    # Calculate risk score based on indicators
    risk = analysis.get("risk_score", 0)
    indicators = analysis.get("risk_indicators", [])
    if risk == 0 and indicators:
        risk = 15
        for ind in indicators:
            ind_lower = ind.lower()
            if any(k in ind_lower for k in ["executable", "malware", "payload", "double extension", "high file entropy"]):
                risk = max(risk, 85)
            elif any(k in ind_lower for k in ["vba", "macro", "encrypted", "bomb", "credential", "brand"]):
                risk = max(risk, 65)
            elif any(k in ind_lower for k in ["qr", "link", "warning", "redirect"]):
                risk = max(risk, 40)
    elif risk == 0:
        risk = 10

    # Map verdict for UI
    if risk >= 75 or analysis.get("malware_detected") or analysis.get("doc_category") in ["MALWARE", "EXECUTABLE"]:
        verdict = "MALICIOUS"
    elif risk >= 35 or analysis.get("is_double_ext") or len(indicators) > 0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    analysis["risk_score"] = risk
    analysis["verdict"] = verdict
    analysis["filename"] = sanitized_filename
    analysis["file_size_bytes"] = len(content)
    now_iso = datetime.now(timezone.utc).isoformat()
    analysis["scan_timestamp"] = now_iso
    
    # Save the scanned attachment results record to MongoDB
    doc = {
        "user_id": str(current_user.id),
        "filename": sanitized_filename,
        "file_size_bytes": len(content),
        "verdict": verdict,
        "risk_score": risk,
        "analysis": analysis,
        "created_at": datetime.now(timezone.utc)
    }
    res = await db_manager.db["attachments"].insert_one(doc)
    analysis["id"] = str(res.inserted_id)
    analysis["attachment_id"] = str(res.inserted_id)
    
    # Mirror email files (.eml, .msg) directly into emails collection so they appear in Inbox
    ext = os.path.splitext(sanitized_filename)[1].lower()
    meta = analysis.get("embedded_metadata", {})
    if ext in [".eml", ".msg"] or meta.get("subject"):
        email_subj = meta.get("subject") or sanitized_filename
        email_from = meta.get("from") or "sender@domain.com"
        email_to = meta.get("to") or current_user.email
        email_body = analysis.get("extracted_text") or f"Scanned email file: {sanitized_filename}"
        
        email_doc = {
            "user_id": str(current_user.id),
            "from_address": email_from,
            "to_address": email_to,
            "subject": email_subj,
            "body_text": email_body,
            "body_html": f"<pre>{email_body}</pre>",
            "date": datetime.now(timezone.utc),
            "processing_status": "completed",
            "analysis": {
                "verdict": verdict,
                "risk_score": risk,
                "confidence": 0.95,
                "threat_types": [verdict.lower()] if verdict != "SAFE" else [],
                "indicators": indicators,
                "timestamp": now_iso
            },
            "source": "attachment_upload",
            "attachment_id": str(res.inserted_id),
            "filename": sanitized_filename
        }
        try:
            await db_manager.db["emails"].insert_one(email_doc)
        except Exception:
            pass
            
    return analysis

@router.post("/ocr")
@trace_span(name="attachment_ocr")
async def process_file_ocr(
    file: UploadFile = File(...),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Explicitly perform character scanning on images or screenshots."""
    _ = sanitize_and_validate_filename(file.filename)
    content = await file.read()
    res = await AttachmentAnalyzerService.extract_ocr(content)
    return res

@router.post("/qr")
@trace_span(name="attachment_qr")
async def process_file_qr(
    file: UploadFile = File(...),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Explicitly detect and decode QR destination codes in uploaded graphics."""
    _ = sanitize_and_validate_filename(file.filename)
    content = await file.read()
    res = await AttachmentAnalyzerService.extract_qr(content)
    return res

@router.get("/{id}")
async def get_attachment_by_id(
    id: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Retrieve stored attachment metadata details by database ID."""
    if db_manager.db is None:
         raise RuntimeError("Database connection not ready.")
         
    if not ObjectId.is_valid(id):
         raise HTTPException(status_code=400, detail="Invalid attachment identifier.")
         
    rec = await db_manager.db["attachments"].find_one({"_id": ObjectId(id)})
    if not rec:
         raise HTTPException(status_code=404, detail="Attachment record not found.")
         
    if rec.get("user_id") != str(current_user.id):
         raise HTTPException(status_code=403, detail="Forbidden.")
         
    analysis = rec["analysis"]
    analysis["id"] = str(rec["_id"])
    return analysis

@router.get("/report/{id}")
async def get_attachment_security_report(
    id: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Compile comprehensive risk analysis and visual impersonation reports for audited attachments."""
    if db_manager.db is None:
         raise RuntimeError("Database connection not ready.")
         
    if not ObjectId.is_valid(id):
         raise HTTPException(status_code=400, detail="Invalid attachment identifier.")
         
    rec = await db_manager.db["attachments"].find_one({"_id": ObjectId(id)})
    if not rec:
         raise HTTPException(status_code=404, detail="Attachment record not found.")
         
    if rec.get("user_id") != str(current_user.id):
         raise HTTPException(status_code=403, detail="Forbidden.")
         
    analysis = rec["analysis"]
    return {
        "attachment_id": id,
        "filename": rec.get("filename"),
        "doc_category": analysis.get("doc_category"),
        "entropy": analysis.get("entropy"),
        "risk_indicators": analysis.get("risk_indicators", []),
        "extracted_text_preview": (analysis.get("extracted_text") or "")[:200],
        "qr_links": analysis.get("qr_links", [])
    }

@router.get("/")
async def list_attachments(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Retrieve historical scanned attachments for the current user."""
    if db_manager.db is None:
        return []
    cursor = db_manager.db["attachments"].find(
        {"user_id": str(current_user.id)}
    ).sort("created_at", -1).skip(skip).limit(limit)
    recs = await cursor.to_list(length=limit)
    results = []
    for r in recs:
        analysis = r.get("analysis", {})
        created_val = r.get("created_at")
        results.append({
            "attachment_id": str(r["_id"]),
            "filename": r.get("filename", "unknown"),
            "file_size_bytes": r.get("file_size_bytes", 0),
            "verdict": r.get("verdict", "SAFE"),
            "risk_score": r.get("risk_score", 0),
            "scan_timestamp": created_val.isoformat() if hasattr(created_val, "isoformat") else str(created_val),
            "indicators": analysis.get("risk_indicators", []),
            "analysis": analysis
        })
    return results
