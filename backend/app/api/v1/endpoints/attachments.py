from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from bson import ObjectId
from app.api.dependencies.auth import get_current_active_user
from app.models.user import UserInDB
from app.database.connection import db_manager
from app.services.attachment_analyzer import AttachmentAnalyzerService
from app.telemetry.otel import trace_span

import os
import re

ALLOWED_EXTENSIONS = {
    "pdf", "docx", "xlsx", "pptx", "png", "jpg", "jpeg", "gif", "zip", "txt", "csv", "eml"
}

def sanitize_and_validate_filename(filename: str) -> str:
    """Sanitize the uploaded file name to prevent path traversal and double extension attacks."""
    if not filename:
        raise HTTPException(status_code=400, detail="Filename is missing.")
        
    # Prevent Path Traversal (e.g. ../../../etc/passwd)
    clean_base = os.path.basename(filename)
    
    # Restrict to safe character-sets
    sanitized = re.sub(r'[^a-zA-Z0-9._-]', '', clean_base)
    
    # Check for Double Extension Attacks (e.g. exploit.png.exe)
    parts = sanitized.split('.')
    if len(parts) > 2:
        # Check all suffix extensions
        for ext in parts[1:]:
            if ext.lower() not in ALLOWED_EXTENSIONS:
                 raise HTTPException(
                     status_code=400, 
                     detail=f"Double extension validation failed on suffix component '{ext}'."
                 )
                 
    # Validate final extension component
    ext = parts[-1].lower() if len(parts) > 1 else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type extension: '.{ext}'."
        )
        
    return sanitized

router = APIRouter()

@router.post("/analyze")
@trace_span(name="attachment_analyze")
async def analyze_attachment_file(
    file: UploadFile = File(...),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Ingest a file attachment, parse structures, and compute security risk indices."""
    sanitized_filename = sanitize_and_validate_filename(file.filename)
    if db_manager.db is None:
          raise RuntimeError("Database connection not ready.")
          
    content = await file.read()
    analysis = await AttachmentAnalyzerService.analyze_attachment(content, sanitized_filename)
    
    # Save the scanned attachment results record to MongoDB
    doc = {
        "user_id": str(current_user.id),
        "filename": sanitized_filename,
        "analysis": analysis
    }
    res = await db_manager.db["attachments"].insert_one(doc)
    analysis["id"] = str(res.inserted_id)
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
