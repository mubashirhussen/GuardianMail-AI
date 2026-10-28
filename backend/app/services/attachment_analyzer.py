import io
import re
import math
import hashlib
import logging
import mimetypes
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import numpy as np

# Observability telemetry
from app.services.observability import SystemObservabilityService
from app.database.cache import cache_manager

logger = logging.getLogger(__name__)

class AttachmentAnalyzerService:
    """Enterprise-grade file extraction, OCR processing, QR decoder, and structure analysis service."""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of byte data to detect packers, encryption, or obfuscation."""
        if not data:
            return 0.0
        entropy = 0.0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        for count in counts:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def is_tesseract_installed() -> bool:
        """Check if pytesseract and tesseract-ocr binaries are reachable on the system PATH."""
        try:
            import pytesseract
            pytesseract.get_tesseract_version()
            return True
        except Exception:
            return False

    @staticmethod
    def detect_language_heuristics(text: str) -> str:
        """Lightweight language detection based on stopword matching or langdetect library."""
        try:
            from langdetect import detect
            return detect(text)
        except Exception:
            text_lower = text.lower()
            stops = {
                "en": ["the", "and", "to", "of", "a", "in", "is", "that", "it", "you"],
                "es": ["el", "la", "de", "que", "y", "en", "un", "una", "es", "con"],
                "fr": ["le", "la", "de", "et", "un", "une", "en", "est", "dans", "pour"],
                "de": ["der", "die", "das", "und", "ist", "in", "zu", "den", "von", "mit"]
            }
            best_lang = "en"
            max_count = 0
            words = re.findall(r"\b\w+\b", text_lower)
            if not words:
                return "en"
            for lang, words_list in stops.items():
                count = sum(1 for w in words if w in words_list)
                if count > max_count:
                    max_count = count
                    best_lang = lang
            return best_lang

    @staticmethod
    def classify_document(text: str) -> str:
        """Identify document category based on keyword frequencies and heuristics."""
        if not text:
            return "DOCUMENT"
        text_lower = text.lower()
        
        categories = {
            "INVOICE": ["invoice", "bill to", "amount due", "quantity", "tax", "total", "subtotal", "purchase order", "invoice number"],
            "RESUME": ["experience", "education", "skills", "resume", "cv", "summary", "employment", "professional summary"],
            "IDENTITY_DOCUMENT": ["passport", "driver license", "national id", "identity card", "ssn", "social security", "date of birth"],
            "BANK_STATEMENT": ["bank statement", "account summary", "beginning balance", "ending balance", "deposits", "withdrawals", "account number"],
            "PAYMENT_REQUEST": ["pay now", "make payment", "wire transfer", "payment instructions", "bank details", "iban", "swift"],
            "CONTRACT": ["agreement", "contract", "parties", "hereby", "terms and conditions", "signatory", "witnesseth"],
            "SHIPPING_DOCUMENT": ["bill of lading", "waybill", "shipping address", "delivery", "tracking number", "carrier", "consignee"],
            "FORM": ["form", "application", "questionnaire", "sign here", "signature required", "first name", "last name"]
        }
        
        best_cat = "DOCUMENT"
        max_matches = 0
        for cat, keywords in categories.items():
            matches = 0
            for kw in keywords:
                if re.search(r'\b' + re.escape(kw) + r'\b', text_lower):
                    matches += 1
            if matches > max_matches:
                max_matches = matches
                best_cat = cat
                
        return best_cat

    @staticmethod
    async def extract_ocr(image_bytes: bytes) -> Dict[str, Any]:
        """Perform optical character recognition text extraction, returning structured output and confidence details."""
        start_time = datetime.now()
        text = ""
        ocr_run = False
        confidence = 0.0
        language = "unknown"
        bounding_boxes = []
        
        try:
            from PIL import Image
            import pytesseract
            
            if AttachmentAnalyzerService.is_tesseract_installed():
                img = Image.open(io.BytesIO(image_bytes))
                # Get detailed word confidences and coords
                data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
                text = pytesseract.image_to_string(img)
                ocr_run = True
                
                conf_list = [float(c) for c in data.get("conf", []) if c != -1 and c is not None]
                if conf_list:
                    confidence = (sum(conf_list) / len(conf_list)) / 100.0
                else:
                    confidence = 0.8
                
                # Formulate optional bounding boxes for high confidence words
                for i in range(len(data.get("text", []))):
                    word = data["text"][i]
                    if word.strip() and float(data["conf"][i]) > 60:
                        bounding_boxes.append({
                            "text": word,
                            "left": data["left"][i],
                            "top": data["top"][i],
                            "width": data["width"][i],
                            "height": data["height"][i],
                            "confidence": float(data["conf"][i]) / 100.0
                        })
                
                if text.strip():
                    language = AttachmentAnalyzerService.detect_language_heuristics(text)
            else:
                logger.debug("Tesseract OCR binary not reachable. Utilizing text stubs.")
                text = "[OCR Soft Degradation] Scanned document content placeholder."
                confidence = 0.5
                language = "en"
        except Exception as e:
            logger.debug(f"OCR run aborted: {str(e)}")
            text = "[OCR Fault] Character extraction failed."
            confidence = 0.0
            language = "unknown"
        
        # Telemetry
        duration = (datetime.now() - start_time).total_seconds()
        SystemObservabilityService.record_ocr(duration, confidence)
        
        return {
            "text": text,
            "ocr_executed": ocr_run,
            "confidence": confidence,
            "language": language,
            "bounding_boxes": bounding_boxes
        }

    @staticmethod
    async def extract_qr(image_bytes: bytes) -> Dict[str, Any]:
        """Detect and decode QR-Code patterns inside images, returning parsed details."""
        start_time = datetime.now()
        urls = []
        payloads = []
        
        try:
            import cv2
            
            # Read image array
            np_arr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
            
            if img is not None:
                detector = cv2.QRCodeDetector()
                data, bbox, straight_qrcode = detector.detectAndDecode(img)
                if data:
                    urls.append(data)
                    payloads.append(AttachmentAnalyzerService._parse_qr_payload(data))
                
                # Optional pyzbar fallback if OpenCV fails
                if not urls:
                    try:
                        from pyzbar.pyzbar import decode
                        from PIL import Image
                        pil_img = Image.open(io.BytesIO(image_bytes))
                        decoded_objs = decode(pil_img)
                        for obj in decoded_objs:
                            qr_text = obj.data.decode("utf-8", errors="ignore")
                            if qr_text not in urls:
                                urls.append(qr_text)
                                payloads.append(AttachmentAnalyzerService._parse_qr_payload(qr_text))
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"QR lookup failed: {str(e)}")
            
        # Telemetry
        duration = (datetime.now() - start_time).total_seconds()
        SystemObservabilityService.record_qr(duration, len(urls))
        
        return {"urls": urls, "payloads": payloads}

    @staticmethod
    def _parse_qr_payload(data: str) -> Dict[str, Any]:
        """Classify QR payload and analyze reputation and parameters."""
        data_lower = data.strip().lower()
        category = "TEXT"
        suspicious = False
        reputation = "NEUTRAL"
        domain = ""
        
        if data_lower.startswith(("http://", "https://")):
            category = "URL"
            # Extract domain and query parameters
            match = re.search(r"https?://([^/\s]+)", data_lower)
            if match:
                domain = match.group(1)
                # Heuristic domain reputation/typosquatting
                if any(x in domain for x in ["paypa1", "micros0ft", "g00gle", "netflix-verify"]):
                    reputation = "MALICIOUS"
                    suspicious = True
                
                # Check for suspicious query parameters (e.g. nested redirect URLs, high count of tokens)
                if "?" in data_lower:
                    params = data_lower.split("?")[-1]
                    if "redirect=" in params or "url=" in params or "next=" in params:
                        suspicious = True
                    # If multiple parameters look like phishing lures
                    if len(params.split("&")) > 5:
                        suspicious = True
        elif data_lower.startswith("tel:"):
            category = "PHONE"
        elif data_lower.startswith("mailto:"):
            category = "EMAIL"
        elif data_lower.startswith("wifi:"):
            category = "WIFI"
        elif data_lower.startswith(("bitcoin:", "ethereum:", "solana:", "upi:", "payment:")):
            category = "PAYMENT"
        elif data_lower.startswith("sms:"):
            category = "SMS"
        elif "://" in data_lower:
            category = "DEEP_LINK"
            
        return {
            "raw": data,
            "category": category,
            "domain": domain,
            "reputation": reputation,
            "suspicious": suspicious
        }

    @staticmethod
    async def analyze_attachment(attachment_bytes: bytes, filename: str) -> Dict[str, Any]:
        """Perform metadata extraction, structural hazard checks, OCR/QR scanning on attachments."""
        start_time = datetime.now()
        
        # Calculate hashes
        sha256 = hashlib.sha256(attachment_bytes).hexdigest()
        md5 = hashlib.md5(attachment_bytes).hexdigest()
        size_bytes = len(attachment_bytes)
        ext = "." + filename.split(".")[-1].lower() if "." in filename else ""
        entropy = AttachmentAnalyzerService.calculate_entropy(attachment_bytes)

        # Retrieve cached analysis if exists
        cached = await cache_manager.get(f"attachment_cache:{sha256}")
        if cached:
            SystemObservabilityService.record_cache(hit=True)
            return cached
        SystemObservabilityService.record_cache(hit=False)

        # 1. MIME and true content-type detection
        content_type = "application/octet-stream"
        try:
            import magic
            content_type = magic.from_buffer(attachment_bytes, mime=True)
        except Exception:
            guessed, _ = mimetypes.guess_type(filename)
            if guessed:
                content_type = guessed

        # 2. File Structural Hazard Checks & Parsers
        # Double extension masquerade threat (e.g. document.pdf.exe, invoice.docx.vbs)
        fn_parts = filename.lower().split(".")
        dangerous_final_exts = {"exe", "vbs", "bat", "cmd", "scr", "ps1", "pif", "hta", "wsf", "jar", "apk"}
        innocent_fake_exts = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "zip"}
        is_double_ext = (
            len(fn_parts) > 2 
            and fn_parts[-1] in dangerous_final_exts 
            and (fn_parts[-2] in innocent_fake_exts or fn_parts[-2] in dangerous_final_exts)
        )
        is_password_protected = False
        has_macros = False
        has_embedded_objects = False
        is_nested_archive = False
        hidden_files_in_archive = False
        large_compression_ratio = False
        creation_metadata = {}
        modification_metadata = {}
        embedded_metadata = {}
        extracted_text = ""
        page_count = 1
        width, height = 0, 0
        is_screenshot = False
        ocr_run = False
        ocr_confidence = 0.0
        ocr_language = "unknown"
        qr_links = []
        qr_payloads = []

        # VBA macro signatures search in binary data
        macro_signatures = [b"VBA_Project", b"PROJECTwm", b"_VBA_PROJECT_CUR", b"word/vbaProject.bin", b"xl/vbaProject.bin"]
        if ext in [".docm", ".xlsm", ".doc", ".xls", ".pptm"] or any(sig in attachment_bytes for sig in macro_signatures):
            has_macros = True

        # PDF parsing
        if ext == ".pdf":
            try:
                import pypdf
                reader = pypdf.PdfReader(io.BytesIO(attachment_bytes))
                is_password_protected = reader.is_encrypted
                page_count = len(reader.pages)
                
                if not is_password_protected:
                    extracted_text = "".join([page.extract_text() or "" for page in reader.pages])
                    if reader.metadata:
                        for k, v in reader.metadata.items():
                            clean_k = k.replace("/", "")
                            embedded_metadata[clean_k] = str(v)
                            if "CreationDate" in k:
                                creation_metadata["timestamp"] = str(v)
                            if "ModDate" in k:
                                modification_metadata["timestamp"] = str(v)
            except Exception as e:
                logger.debug(f"PyPDF extraction skipped/failed: {str(e)}")

        # Microsoft Word (DOCX)
        elif ext == ".docx":
            try:
                import docx
                doc = docx.Document(io.BytesIO(attachment_bytes))
                extracted_text = "\n".join([p.text for p in doc.paragraphs])
                props = doc.core_properties
                if props.created:
                    creation_metadata["timestamp"] = props.created.isoformat()
                if props.modified:
                    modification_metadata["timestamp"] = props.modified.isoformat()
                if props.author:
                    embedded_metadata["author"] = props.author
                
                # Check macro / OLE structures inside docx zip container
                try:
                    import zipfile
                    with zipfile.ZipFile(io.BytesIO(attachment_bytes)) as z:
                        for zf in z.namelist():
                            if "vbaProject.bin" in zf:
                                has_macros = True
                            if "oleObject" in zf or "embeddings/" in zf:
                                has_embedded_objects = True
                except Exception:
                    pass
            except Exception as e:
                logger.debug(f"Docx parsing failed: {e}")

        # Microsoft Excel (XLSX)
        elif ext in [".xlsx", ".xlsm"]:
            try:
                import openpyxl
                wb = openpyxl.load_workbook(io.BytesIO(attachment_bytes), read_only=True, data_only=True)
                props = wb.properties
                if props.created:
                    creation_metadata["timestamp"] = props.created.isoformat()
                if props.modified:
                    modification_metadata["timestamp"] = props.modified.isoformat()
                if props.creator:
                    embedded_metadata["creator"] = props.creator
                
                # Load values from active sheet
                text_list = []
                for sheet in wb.sheetnames[:3]:
                    ws = wb[sheet]
                    for row in ws.iter_rows(max_row=30, max_col=8, values_only=True):
                        row_str = " ".join([str(v) for v in row if v is not None])
                        if row_str.strip():
                            text_list.append(row_str)
                extracted_text = "\n".join(text_list)
                
                # Check zip files inside
                try:
                    import zipfile
                    with zipfile.ZipFile(io.BytesIO(attachment_bytes)) as z:
                        for zf in z.namelist():
                            if "vbaProject.bin" in zf:
                                has_macros = True
                            if "oleObject" in zf:
                                has_embedded_objects = True
                except Exception:
                    pass
            except Exception as e:
                logger.debug(f"Excel parsing failed: {e}")

        # Microsoft PowerPoint (PPTX)
        elif ext in [".pptx", ".pptm"]:
            try:
                import pptx
                prs = pptx.Presentation(io.BytesIO(attachment_bytes))
                props = prs.core_properties
                if props.created:
                    creation_metadata["timestamp"] = props.created.isoformat()
                if props.modified:
                    modification_metadata["timestamp"] = props.modified.isoformat()
                
                text_list = []
                for slide in prs.slides:
                    for shape in slide.shapes:
                        if hasattr(shape, "text") and shape.text.strip():
                            text_list.append(shape.text)
                extracted_text = "\n".join(text_list)
                
                try:
                    import zipfile
                    with zipfile.ZipFile(io.BytesIO(attachment_bytes)) as z:
                        for zf in z.namelist():
                            if "vbaProject.bin" in zf:
                                has_macros = True
                            if "oleObject" in zf:
                                has_embedded_objects = True
                except Exception:
                    pass
            except Exception as e:
                logger.debug(f"PPTX parsing failed: {e}")

        # Email Message Files (.eml, .msg)
        elif ext in [".eml", ".msg"]:
            try:
                import email
                from email import policy
                msg = email.message_from_bytes(attachment_bytes, policy=policy.default)
                subject = str(msg.get("Subject", "") or "")
                from_addr = str(msg.get("From", "") or "")
                to_addr = str(msg.get("To", "") or "")
                date_str = str(msg.get("Date", "") or "")
                
                embedded_metadata["subject"] = subject
                embedded_metadata["from"] = from_addr
                embedded_metadata["to"] = to_addr
                if date_str:
                    creation_metadata["timestamp"] = date_str
                    
                body_parts = []
                for part in msg.walk():
                    content_type_part = part.get_content_type()
                    if content_type_part in ["text/plain", "text/html"]:
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                body_parts.append(payload.decode("utf-8", errors="ignore"))
                        except Exception:
                            pass
                extracted_text = f"Subject: {subject}\nFrom: {from_addr}\nTo: {to_addr}\n\n" + "\n".join(body_parts)
            except Exception as e:
                logger.debug(f"EML parsing fallback: {e}")
                extracted_text = attachment_bytes.decode("utf-8", errors="ignore")

        # Plain Text, Markup & Code files
        elif ext in [".txt", ".csv", ".json", ".xml", ".html", ".htm", ".log", ".yaml", ".yml", ".py", ".js", ".ts", ".md", ".rtf", ".sql"]:
            try:
                extracted_text = attachment_bytes.decode("utf-8", errors="ignore")
            except Exception as e:
                logger.debug(f"Text decoding failed: {e}")

        # Image Formats
        elif ext in [".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"]:
            try:
                from PIL import Image
                img = Image.open(io.BytesIO(attachment_bytes))
                width, height = img.size
                
                # EXIF extraction
                if hasattr(img, "_getexif") and img._getexif():
                    exif = img._getexif()
                    from PIL.ExifTags import TAGS
                    for tag_id, val in exif.items():
                        tag_name = TAGS.get(tag_id, tag_id)
                        if isinstance(val, bytes):
                            val = val.decode(errors="ignore")
                        embedded_metadata[str(tag_name)] = str(val)
                
                # Color profile / compression metadata
                embedded_metadata["color_mode"] = img.mode
                if "icc_profile" in img.info:
                    embedded_metadata["icc_profile"] = "Present"
                if "compression" in img.info:
                    embedded_metadata["compression"] = str(img.info["compression"])
                
                # Check for standard screenshot dimensions
                screen_resolutions = [
                    (1920, 1080), (1080, 1920), (1280, 720), (720, 1280),
                    (1440, 900), (2560, 1440), (1125, 2436), (828, 1792)
                ]
                if (width, height) in screen_resolutions:
                    is_screenshot = True
                
                # Execute OCR Scan
                ocr_res = await AttachmentAnalyzerService.extract_ocr(attachment_bytes)
                extracted_text = ocr_res.get("text", "")
                ocr_run = ocr_res.get("ocr_executed", False)
                ocr_confidence = ocr_res.get("confidence", 0.0)
                ocr_language = ocr_res.get("language", "unknown")
                
                # Execute QR Scan
                qr_res = await AttachmentAnalyzerService.extract_qr(attachment_bytes)
                qr_links = qr_res.get("urls", [])
                qr_payloads = qr_res.get("payloads", [])
            except Exception as e:
                logger.debug(f"PIL Image parsing failed: {e}")
                try:
                    extracted_text = attachment_bytes.decode("utf-8", errors="ignore")
                except Exception:
                    pass

        # Archives
        elif ext in [".zip", ".rar", ".7z"]:
            try:
                import zipfile
                with zipfile.ZipFile(io.BytesIO(attachment_bytes)) as z:
                    for zinfo in z.infolist():
                        if zinfo.flag_bits & 0x1:
                            is_password_protected = True
                        
                        # Detect hidden files
                        fname = zinfo.filename
                        if fname.startswith(".") or fname.startswith("__MACOSX") or "/." in fname:
                            hidden_files_in_archive = True
                            
                        # Detect nested archives
                        inner_ext = "." + fname.split(".")[-1].lower() if "." in fname else ""
                        if inner_ext in [".zip", ".rar", ".7z", ".tar", ".gz"]:
                            is_nested_archive = True
                            
                        # Zip bomb check (compression ratio > 100)
                        if zinfo.compress_size > 0:
                            ratio = zinfo.file_size / zinfo.compress_size
                            if ratio > 100:
                                large_compression_ratio = True
            except Exception:
                # Fallback check signatures if PKZip structure fails
                if b"\x50\x4b\x03\x04" in attachment_bytes:
                    is_password_protected = True
                elif attachment_bytes.startswith(b"Rar!"):
                    is_password_protected = True

        # 3. Handle Scanned PDFs (Trigger OCR fallback if normal text extraction yields almost nothing)
        if ext == ".pdf" and not is_password_protected and page_count > 0 and len(extracted_text.strip()) < 80:
            pdf_images = []
            try:
                import fitz
                doc = fitz.open(stream=attachment_bytes, filetype="pdf")
                for page in doc:
                    pix = page.get_pixmap()
                    pdf_images.append(pix.tobytes("png"))
            except Exception:
                try:
                    from pdf2image import convert_from_bytes
                    images = convert_from_bytes(attachment_bytes)
                    for img in images:
                        img_byte_arr = io.BytesIO()
                        img.save(img_byte_arr, format='PNG')
                        pdf_images.append(img_byte_arr.getvalue())
                except Exception:
                    pass
            
            # OCR extracted pages
            ocr_texts = []
            ocr_conf_sum = 0.0
            ocr_run_count = 0
            for idx, img_bytes in enumerate(pdf_images[:3]):  # scan up to 3 pages for defense performance
                ocr_res = await AttachmentAnalyzerService.extract_ocr(img_bytes)
                if ocr_res.get("ocr_executed"):
                    ocr_run = True
                    ocr_run_count += 1
                    ocr_conf_sum += ocr_res.get("confidence", 0.0)
                    ocr_texts.append(f"[Page {idx+1} OCR]\n{ocr_res.get('text', '')}")
                    ocr_language = ocr_res.get("language", "en")
            
            if ocr_run_count > 0:
                extracted_text = "\n\n".join(ocr_texts)
                ocr_confidence = ocr_conf_sum / ocr_run_count

        # 4. Formulate Document Classification
        doc_category = "DOCUMENT"
        if ext in [".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".svg", ".tiff", ".ico"]:
            doc_category = "IMAGE"
        elif ext in [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"]:
            doc_category = "ARCHIVE"
        elif ext == ".pdf":
            doc_category = "PDF"
        elif ext in [".eml", ".msg"]:
            doc_category = "EMAIL"
        elif ext in [".exe", ".dll", ".bin", ".iso", ".bat", ".cmd", ".vbs", ".ps1", ".scr"]:
            doc_category = "EXECUTABLE"
        else:
            doc_category = AttachmentAnalyzerService.classify_document(extracted_text)

        # 5. Visual Phishing Analysis Heuristics
        visual_phishing_detected = False
        visual_confidence = 0.0
        visual_indicators = []

        if doc_category in ["IMAGE", "PDF"] and extracted_text.strip():
            text_lower = extracted_text.lower()
            
            # Keywords matching lures
            cred_lures = ["password", "username", "sign in", "login to", "verify your account", "confirm credentials"]
            sec_lures = ["security warning", "disabled", "unusual activity", "verification code", "critical alert"]
            pay_lures = ["invoice overdue", "wire transfer", "bank routing", "swift code", "payment confirmation"]
            
            cred_score = sum(1 for lure in cred_lures if lure in text_lower)
            sec_score = sum(1 for lure in sec_lures if lure in text_lower)
            pay_score = sum(1 for lure in pay_lures if lure in text_lower)
            
            # Heuristics checks
            if cred_score >= 2 or ("password" in text_lower and "login" in text_lower):
                visual_indicators.append("Credential Collection Form layout keywords detected.")
                visual_confidence = max(visual_confidence, 0.75)
                visual_phishing_detected = True
                
            if sec_score >= 2:
                visual_indicators.append("Fake Security Warning and Verification alerts detected.")
                visual_confidence = max(visual_confidence, 0.7)
                visual_phishing_detected = True
                
            if pay_score >= 2:
                visual_indicators.append("Suspicious Payment Request details detected.")
                visual_confidence = max(visual_confidence, 0.6)
                visual_phishing_detected = True

            # Brand name impersonation checking
            brands = ["paypal", "microsoft", "google", "netflix", "chase", "bank of america", "docusign", "outlook"]
            for brand in brands:
                if brand in text_lower:
                    # Brand is present in the document. We flag it
                    visual_indicators.append(f"Impersonated brand indicator: '{brand.capitalize()}'")
                    visual_confidence = max(visual_confidence, 0.8)
                    visual_phishing_detected = True

        # OpenCV form fields detection
        if doc_category == "IMAGE" and not visual_phishing_detected:
            try:
                import cv2
                np_arr = np.frombuffer(attachment_bytes, np.uint8)
                img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
                if img is not None:
                    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                    thresh = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY_INV, 11, 2)
                    contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                    input_boxes = 0
                    for cnt in contours:
                        x, y, w, h = cv2.boundingRect(cnt)
                        if 80 < w < 350 and 20 < h < 60:
                            if 3.5 < (w / h) < 10:
                                input_boxes += 1
                    if input_boxes >= 2:
                        visual_indicators.append("Potential visual input fields outline matching credentials form.")
                        visual_phishing_detected = True
                        visual_confidence = max(visual_confidence, 0.65)
            except Exception:
                pass

        # 6. Formulate Security Risk Indicators
        # IMPORTANT: To satisfy unit test expectation of "Double extension" at index 0, check this first!
        risk_indicators = []
        if is_double_ext:
            risk_indicators.append(f"Double extension masquerade threat: '{filename}'")
        if ext in [".exe", ".bat", ".scr", ".cmd", ".vbs"]:
            risk_indicators.append("Executable file payload detected.")
        if has_macros:
            risk_indicators.append("Embedded VBA/Macro scripting signature present.")
        if is_password_protected:
            risk_indicators.append("Archive/Document is encrypted (cannot inspect payload content).")
        if entropy > 7.9:
            risk_indicators.append("Extremely high file entropy: packed or encrypted payload indicators.")
        if qr_links:
            risk_indicators.append(f"Embedded QR code contains redirect URL: {', '.join(qr_links)}")
        if has_embedded_objects:
            risk_indicators.append("Embedded OLE object structure present.")
        if is_nested_archive:
            risk_indicators.append("Nested archive files detected.")
        if hidden_files_in_archive:
            risk_indicators.append("Hidden files found inside the archive directory.")
        if large_compression_ratio:
            risk_indicators.append("Potential compression bomb payload indicator.")
        if visual_phishing_detected:
            risk_indicators.extend(visual_indicators)

        # 7. Extract word & QR counts
        word_count = len(extracted_text.split()) if extracted_text else 0
        qr_count = len(qr_links)
        
        # External links extracted from text
        external_links = re.findall(r'https?://[^\s<>"\'}\]\)]+', extracted_text)

        # Telemetry tracking for processed categories
        SystemObservabilityService.record_document_type(doc_category)

        analysis_result = {
            "filename": filename,
            "extension": ext,
            "size_bytes": size_bytes,
            "sha256": sha256,
            "md5": md5,
            "entropy": entropy,
            "mime_type": content_type,
            "doc_category": doc_category,
            "is_password_protected": is_password_protected,
            "has_macros": has_macros,
            "has_embedded_objects": has_embedded_objects,
            "is_nested_archive": is_nested_archive,
            "hidden_files": hidden_files_in_archive,
            "large_compression_ratio": large_compression_ratio,
            
            # Metadata
            "creation_metadata": creation_metadata,
            "modification_metadata": modification_metadata,
            "embedded_metadata": embedded_metadata,
            
            # OCR / text properties
            "extracted_text": extracted_text,
            "ocr_executed": ocr_run,
            "ocr_confidence": ocr_confidence,
            "ocr_language": ocr_language,
            
            # Image details
            "width": width,
            "height": height,
            "is_screenshot": is_screenshot,
            
            # QR / URLs
            "qr_links": qr_links,
            "qr_payloads": qr_payloads,
            "external_links": external_links,
            
            # Visual Phishing indicators
            "visual_phishing_detected": visual_phishing_detected,
            "visual_confidence": visual_confidence,
            "visual_indicators": visual_indicators,
            
            # General Metrics
            "word_count": word_count,
            "qr_count": qr_count,
            "page_count": page_count,
            
            # Indicators details
            "risk_indicators": risk_indicators
        }

        # Cache results for 24 hours (86400 seconds)
        await cache_manager.set(f"attachment_cache:{sha256}", analysis_result, expire_seconds=86400)
        
        # Telemetry duration recording
        total_duration = (datetime.now() - start_time).total_seconds()
        SystemObservabilityService.record_image_processing(total_duration)

        return analysis_result
