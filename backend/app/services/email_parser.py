import re
import email
import hashlib
import urllib.parse
import logging
from email import policy
from email.parser import BytesParser
from typing import Dict, Any, List, Tuple, Optional
from bs4 import BeautifulSoup
import bleach
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class EmailParserService:
    """Enterprise-grade Email Processing & Parsing Engine for MIME structure normalization and security checks."""

    @staticmethod
    def parse_eml_bytes(eml_content: bytes) -> Dict[str, Any]:
        """Convert raw eml byte stream into structured, normalized, and enriched email components."""
        try:
            msg = BytesParser(policy=policy.default).parsebytes(eml_content)
        except Exception as e:
            logger.error(f"MIME parse failed: {str(e)}")
            # Fallback parsing shell
            msg = email.message_from_bytes(eml_content, policy=policy.default)

        # 1. Header Extraction & Normalization
        message_id = msg.get("Message-ID", "").strip("<>")
        in_reply_to = msg.get("In-Reply-To", "").strip("<>")
        
        # References header splitting
        ref_header = msg.get("References", "")
        references = [ref.strip("<>") for ref in ref_header.split() if ref.strip()]

        subject = msg.get("Subject", "No Subject")
        from_header = msg.get("From", "")
        to_header = msg.get_all("To", [])
        cc_header = msg.get_all("Cc", [])
        bcc_header = msg.get_all("Bcc", [])

        to_addresses = []
        for to_addr in to_header:
            to_addresses.extend([addr.strip() for addr in str(to_addr).split(",") if addr.strip()])
            
        cc_addresses = []
        for cc_addr in cc_header:
            cc_addresses.extend([addr.strip() for addr in str(cc_addr).split(",") if addr.strip()])
            
        bcc_addresses = []
        for bcc_addr in bcc_header:
            bcc_addresses.extend([addr.strip() for addr in str(bcc_addr).split(",") if addr.strip()])

        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")
        date_str = msg.get("Date", "")
        
        date_val = None
        if date_str:
            try:
                date_val = email.utils.parsedate_to_datetime(date_str)
            except Exception:
                pass

        # 2. Body Parsing (Plain text & HTML extraction)
        plain_body, html_body = EmailParserService._extract_body(msg)

        # 3. HTML Sanitization
        sanitized_html = EmailParserService.sanitize_html(html_body)

        # 4. Attachment Metadata Ingestion
        attachments = EmailParserService._extract_attachments(msg)

        # 5. Domain Normalization (From / To / CC / BCC)
        sender_details = EmailParserService.normalize_email_address(from_header)
        
        # Count inline images
        images_count = 0
        if html_body:
             try:
                  soup = BeautifulSoup(html_body, "html.parser")
                  images_count = len(soup.find_all("img"))
             except Exception:
                  pass

        # 6. Metrics & Enrichment
        metrics = EmailParserService.calculate_metrics(
            plain_body=plain_body,
            html_body=html_body,
            attachments=attachments,
            images_count=images_count,
            message_size=len(eml_content)
        )

        # 7. URL and Deep Link Extraction
        urls = EmailParserService.extract_links(plain_body, html_body)

        # Compile normalized dict
        return {
            "message_id": message_id,
            "in_reply_to": in_reply_to,
            "references": references,
            "subject": subject,
            "from_address": sender_details.get("email"),
            "sender_name": sender_details.get("display_name"),
            "sender_domain": sender_details.get("domain"),
            "sender_tld": sender_details.get("tld"),
            "to_address": to_addresses,
            "cc_address": cc_addresses,
            "bcc_address": bcc_addresses,
            "reply_to": reply_to,
            "return_path": return_path,
            "date": date_val,
            "body_plain": plain_body,
            "body_html": sanitized_html,
            "attachments": attachments,
            "urls": urls,
            "metrics": metrics,
            "raw_msg": msg
        }

    @staticmethod
    def sanitize_html(html_body: str) -> str:
        """Strip dangerous tags, scripts, tracking pixels, and inline scripts using bleach."""
        if not html_body:
            return ""
        # Bleach clean settings
        allowed_tags = [
            'a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 'i', 'li', 'ol', 'strong', 'ul',
            'p', 'br', 'span', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'table', 'tr', 'td', 'th',
            'thead', 'tbody', 'tfoot', 'img'
        ]
        allowed_attrs = {
            'a': ['href', 'title', 'target'],
            'abbr': ['title'],
            'acronym': ['title'],
            'img': ['src', 'alt', 'title', 'width', 'height']
        }
        
        try:
            # First parse through BeautifulSoup to strip out script blocks, iframe structures, tracking pixels
            soup = BeautifulSoup(html_body, "html.parser")
            for element in soup(["script", "style", "iframe", "object", "embed"]):
                element.decompose()
                
            # Filter tracking pixels: img tag with height or width <= 1px
            for img in soup.find_all("img"):
                width_attr = img.get("width", "0")
                height_attr = img.get("height", "0")
                style_attr = img.get("style", "")
                if width_attr in ["1", "0"] or height_attr in ["1", "0"] or "width:1px" in style_attr.replace(" ", ""):
                    img.decompose()

            cleaned_html = str(soup)
            try:
                from bleach.css_sanitizer import CSSSanitizer
                css_sanitizer = CSSSanitizer()
                sanitized = bleach.clean(cleaned_html, tags=allowed_tags, attributes=allowed_attrs, css_sanitizer=css_sanitizer, strip=True)
            except Exception:
                sanitized = bleach.clean(cleaned_html, tags=allowed_tags, attributes=allowed_attrs, strip=True)
            return sanitized
        except Exception as e:
            logger.error(f"HTML sanitization failed: {str(e)}")
            return ""

    @staticmethod
    def extract_links(plain_body: str, html_body: str) -> List[Dict[str, Any]]:
        """Deep extract and structure all unique hyperlinks, categorizing by schema and parameters."""
        url_pattern = re.compile(
            r'(?:https?|ftp|mailto|tel)://[^\s<>"\'}\]\)]+|www\.[^\s<>"\'}\]\)]+',
            re.IGNORECASE
        )
        
        raw_items = []
        
        # Parse URLs in text body
        if plain_body:
             for match in url_pattern.finditer(plain_body):
                  url_str = match.group(0)
                  raw_items.append({"url": url_str, "display_text": "Plain Text Link"})

        # Parse href and display text from HTML
        if html_body:
            try:
                soup = BeautifulSoup(html_body, "html.parser")
                for link in soup.find_all("a", href=True):
                    raw_items.append({
                        "url": link["href"],
                        "display_text": link.get_text().strip() or "Hyperlink"
                    })
            except Exception:
                pass

        processed_links = []
        seen_urls = set()
        
        for item in raw_items:
             url = item["url"]
             display_text = item["display_text"]
             
             if url in seen_urls:
                  continue
             seen_urls.add(url)
             
             # Resolve protocol-less links like www.google.com
             full_url = url
             if not url.lower().startswith(("http://", "https://", "ftp://", "mailto:", "tel:")):
                  full_url = "http://" + url
                  
             # Extract parsing parts
             parsed = urllib.parse.urlparse(full_url)
             domain = parsed.netloc.lower().lstrip("www.")
             
             # Categorize
             category = "HTTP"
             if parsed.scheme.lower() == "https":
                  category = "HTTPS"
             elif parsed.scheme.lower() == "ftp":
                  category = "FTP"
             elif parsed.scheme.lower() == "mailto":
                  category = "Mailto"
                  domain = parsed.path.split("@")[-1] if "@" in parsed.path else ""
             elif parsed.scheme.lower() == "tel":
                  category = "Telephone"
                  domain = ""

             # Subdomain extraction
             subdomain = ""
             tld = ""
             if domain and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
                  parts = domain.split(".")
                  if len(parts) > 2:
                       subdomain = ".".join(parts[:-2])
                       tld = parts[-1]
                  elif len(parts) == 2:
                       tld = parts[-1]

             processed_links.append({
                 "original_url": url,
                 "normalized_url": full_url,
                 "display_text": display_text,
                 "category": category,
                 "domain": domain,
                 "subdomain": subdomain,
                 "tld": tld,
                 "path": parsed.path,
                 "query_params": urllib.parse.parse_qs(parsed.query),
                 "hash": parsed.fragment
             })

        return processed_links

    @staticmethod
    def normalize_email_address(addr_str: str) -> Dict[str, Any]:
        """Parse email headers to extract display names, email addresses, and subdomains."""
        if not addr_str:
            return {"display_name": "", "email": "", "domain": "", "tld": ""}
            
        try:
            real_name, email_address = email.utils.parseaddr(addr_str)
            email_address = email_address.strip().lower()
            
            domain = ""
            tld = ""
            if "@" in email_address:
                domain = email_address.split("@")[-1]
                parts = domain.split(".")
                if len(parts) >= 2:
                     tld = parts[-1]
                     
            return {
                "display_name": real_name.strip(),
                "email": email_address,
                "domain": domain,
                "tld": tld
            }
        except Exception:
            return {"display_name": "", "email": addr_str.strip().lower(), "domain": "", "tld": ""}

    @staticmethod
    def calculate_metrics(
        plain_body: str,
        html_body: str,
        attachments: List[Any],
        images_count: int,
        message_size: int
    ) -> Dict[str, Any]:
        """Compile statistics, counting character sizes, reading times, and estimating languages."""
        word_count = len(plain_body.split()) if plain_body else 0
        read_time_est = max(1, int(word_count / 200)) # 200 words per minute average
        
        # Simple heuristic language check
        language = "en"
        common_words = {
            "the": "en", "and": "en", "der": "de", "die": "de", "das": "de",
            "le": "fr", "la": "fr", "el": "es", "en": "es", "que": "es"
        }
        words = [w.lower() for w in plain_body.split()[:50]] if plain_body else []
        counts = {"en": 0, "de": 0, "fr": 0, "es": 0}
        for w in words:
             if w in common_words:
                  counts[common_words[w]] += 1
        top_lang = max(counts, key=counts.get)
        if counts[top_lang] > 0:
             language = top_lang

        return {
            "message_size_bytes": message_size,
            "plain_body_size": len(plain_body) if plain_body else 0,
            "html_body_size": len(html_body) if html_body else 0,
            "word_count": word_count,
            "reading_time_minutes": read_time_est,
            "language": language,
            "attachment_count": len(attachments),
            "images_count": images_count,
            "links_count": 0 # Populated in endpoints using parsed urls list
        }

    @staticmethod
    def _extract_body(msg) -> Tuple[str, str]:
        """Walk through email parts and separate plain text and html bodies."""
        plain = ""
        html = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                disposition = str(part.get_content_disposition())
                
                if "attachment" in disposition:
                    continue
                    
                if ct == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        plain += payload.decode(charset, errors="replace")
                    except Exception:
                        pass
                elif ct == "text/html":
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        html += payload.decode(charset, errors="replace")
                    except Exception:
                        pass
        else:
            ct = msg.get_content_type()
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or "utf-8"
                decoded = payload.decode(charset, errors="replace") if payload else ""
                if ct == "text/plain":
                    plain = decoded
                elif ct == "text/html":
                    html = decoded
            except Exception:
                pass
                
        return plain, html

    @staticmethod
    def _extract_attachments(msg) -> List[Dict[str, Any]]:
        """Identify and extract metadata of all embedded attachments."""
        attachments = []
        for part in msg.walk():
            disposition = part.get_content_disposition()
            filename = part.get_filename()
            
            if disposition == "attachment" or filename:
                filename = filename or "unnamed_attachment"
                content_type = part.get_content_type()
                
                try:
                    payload = part.get_payload(decode=True) or b""
                except Exception:
                    payload = b""
                    
                size_bytes = len(payload)
                sha256_hash = hashlib.sha256(payload).hexdigest() if payload else None
                content_id = part.get("Content-ID", "").strip("<>")
                
                attachments.append({
                    "filename": filename,
                    "content_type": content_type,
                    "size_bytes": size_bytes,
                    "sha256_hash": sha256_hash,
                    "content_id": content_id,
                    "is_inline": disposition == "inline" or bool(content_id),
                    "download_status": "completed"
                })
        return attachments

    @staticmethod
    async def reconstruct_thread(msg_id: str, in_reply_to: str, references: List[str], email_repo: Any) -> Dict[str, Any]:
        """Analyze parent message ids to establish thread structures and conversation positions."""
        thread_id = None
        depth = 0
        
        # 1. Lookup parent in_reply_to
        if in_reply_to:
             parent = await email_repo.collection.find_one({"message_id": in_reply_to})
             if parent:
                  thread_id = parent.get("thread_id") or str(parent["_id"])
                  depth = parent.get("thread_depth", 0) + 1
                  
        # 2. Check references if parent is not resolved
        if not thread_id and references:
             for ref in reversed(references):
                  parent_ref = await email_repo.collection.find_one({"message_id": ref})
                  if parent_ref:
                       thread_id = parent_ref.get("thread_id") or str(parent_ref["_id"])
                       depth = max(depth, parent_ref.get("thread_depth", 0) + 1)
                       break
                       
        return {
            "thread_id": thread_id or f"thread_{msg_id[:12] if msg_id else 'rand'}",
            "thread_depth": depth
        }
