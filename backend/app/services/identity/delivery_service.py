"""
Multi-channel delivery service for Identity Verification (Email & SMS).
Integrates with real providers (Resend, SendGrid, SMTP, Twilio Verify, Twilio SMS)
with zero fake success states and full E.164 normalization.
"""

import re
import secrets
import logging
import httpx
from typing import Dict, Any, Optional
from fastapi import HTTPException, status
from app.config.settings import settings

logger = logging.getLogger(__name__)

def generate_secure_otp(length: int = 6) -> str:
    """Generate cryptographically secure numeric one-time verification code."""
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(length))

def normalize_phone_number(phone_raw: str) -> str:
    """
    Normalizes and validates phone numbers to international standard E.164 format.
    Example: '+1 (555) 019-2834' -> '+15550192834'
    """
    cleaned = re.sub(r"[\s\(\)\-\.]", "", phone_raw.strip())
    if not cleaned.startswith("+"):
        if cleaned.isdigit() and len(cleaned) == 10:
            # Default to US/Canada +1 if 10 pure digits supplied without country code
            cleaned = "+1" + cleaned
        else:
            cleaned = "+" + cleaned

    # E.164 pattern: + followed by 7 to 15 digits
    if not re.match(r"^\+[1-9]\d{6,14}$", cleaned):
        raise ValueError(
            f"Invalid phone number format '{phone_raw}'. Must be a valid international phone number with country code (E.164 standard, e.g. +14155552671)."
        )
    return cleaned

def mask_identifier(identifier: str) -> str:
    """Mask email or phone number for safe non-sensitive logging and client confirmation."""
    clean = identifier.strip()
    if "@" in clean:
        parts = clean.split("@", 1)
        name = parts[0]
        domain = parts[1]
        masked_name = name[0] + "***" + (name[-1] if len(name) > 1 else "")
        return f"{masked_name}@{domain}"
    elif clean.startswith("+"):
        return clean[:4] + "***" + clean[-3:]
    return "***"

class IdentityDeliveryService:
    """
    Handles real transactional email and SMS dispatch for GuardianMail AI authentication challenges.
    """

    @classmethod
    def get_email_subject_and_body(cls, purpose: str, code: str) -> tuple[str, str, str]:
        """Generate purpose-specific subject and email templates."""
        purpose_lower = purpose.lower()
        if purpose_lower == "registration":
            subject = "GuardianMail AI - Your Account Verification Code"
            headline = "Verify Your Account Registration"
            instructions = "Please enter this one-time code to activate your GuardianMail AI cybersecurity defense account."
        elif purpose_lower == "password_reset":
            subject = "GuardianMail AI - Password Reset Code"
            headline = "Reset Your Password"
            instructions = "A password reset was requested for your account. Enter this code to verify your identity and set a new password."
        elif purpose_lower == "login_step_up":
            subject = "GuardianMail AI - Sign-in Verification Code"
            headline = "Security Step-Up Verification"
            instructions = "A sign-in attempt requires identity verification. Enter this code to complete authentication."
        else:
            subject = "GuardianMail AI - Identity Verification Code"
            headline = "Confirm Identity"
            instructions = "Enter the verification code below to confirm this security action."

        text_content = f"{headline}\n\nYour 6-digit verification code: {code}\n\n{instructions}\n\nThis code will expire in {settings.AUTH_CODE_TTL_SECONDS // 60} minutes. If you did not make this request, please contact your security administrator immediately."

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #050811; color: #f1f5f9; padding: 24px; }}
            .container {{ max-width: 520px; margin: 0 auto; background: #09132c; border: 1px solid #1e3a8a; border-radius: 12px; padding: 32px; }}
            .header {{ display: flex; align-items: center; margin-bottom: 24px; }}
            .brand {{ font-size: 18px; font-weight: 700; color: #ffffff; }}
            .brand span {{ color: #38bdf8; }}
            .code-box {{ background: #030712; border: 1px solid #0284c7; border-radius: 8px; padding: 20px; text-align: center; margin: 24px 0; }}
            .code {{ font-family: monospace; font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #38bdf8; }}
            .footer {{ font-size: 12px; color: #64748b; margin-top: 24px; border-top: 1px solid #1e293b; padding-top: 16px; }}
          </style>
        </head>
        <body>
          <div class="container">
            <div class="brand">GuardianMail <span>AI</span></div>
            <h2 style="color: #ffffff; margin-top: 16px;">{headline}</h2>
            <p style="color: #94a3b8; font-size: 14px;">{instructions}</p>
            <div class="code-box">
              <div class="code">{code}</div>
            </div>
            <p style="color: #94a3b8; font-size: 13px;">This code expires in <strong>{settings.AUTH_CODE_TTL_SECONDS // 60} minutes</strong>. Never share this code with anyone.</p>
            <div class="footer">
              GuardianMail AI Enterprise Cybersecurity Platform<br>
              Automated Identity & Threat Protection System
            </div>
          </div>
        </body>
        </html>
        """
        return subject, text_content, html_content

    @classmethod
    async def send_email(cls, to_email: str, code: str, purpose: str) -> Dict[str, Any]:
        """
        Deliver verification code to target email using configured provider.
        """
        provider = (settings.EMAIL_PROVIDER or "console").lower()
        subject, text_content, html_content = cls.get_email_subject_and_body(purpose, code)
        masked_dest = mask_identifier(to_email)

        # 1. Resend Provider
        if provider == "resend":
            if not settings.EMAIL_API_KEY:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Email delivery provider 'Resend' is not configured with a valid EMAIL_API_KEY."
                )
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(
                        "https://api.resend.com/emails",
                        headers={
                            "Authorization": f"Bearer {settings.EMAIL_API_KEY}",
                            "Content-Type": "application/json"
                        },
                        json={
                            "from": settings.EMAIL_FROM_ADDRESS,
                            "to": [to_email],
                            "subject": subject,
                            "text": text_content,
                            "html": html_content
                        }
                    )
                    if resp.status_code not in (200, 201):
                        logger.error(f"Resend API error: {resp.status_code} - {resp.text}")
                        raise HTTPException(
                            status_code=status.HTTP_502_BAD_GATEWAY,
                            detail=f"Email delivery failed via Resend: {resp.text}"
                        )
                    res_json = resp.json()
                    logger.info(f"Verification email successfully dispatched to {masked_dest} via Resend")
                    return {"provider": "resend", "status": "sent", "id": res_json.get("id")}
            except httpx.RequestError as e:
                logger.error(f"Network error contacting Resend: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Network error while delivering verification email. Please try again."
                )

        # 2. SendGrid Provider
        elif provider == "sendgrid":
            if not settings.EMAIL_API_KEY:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Email delivery provider 'SendGrid' is not configured with a valid EMAIL_API_KEY."
                )
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(
                        "https://api.sendgrid.com/v3/mail/send",
                        headers={
                            "Authorization": f"Bearer {settings.EMAIL_API_KEY}",
                            "Content-Type": "application/json"
                        },
                        json={
                            "personalizations": [{"to": [{"email": to_email}]}],
                            "from": {"email": settings.EMAIL_FROM_ADDRESS, "name": "GuardianMail AI"},
                            "subject": subject,
                            "content": [
                                {"type": "text/plain", "value": text_content},
                                {"type": "text/html", "value": html_content}
                            ]
                        }
                    )
                    if resp.status_code not in (200, 202):
                        logger.error(f"SendGrid API error: {resp.status_code} - {resp.text}")
                        raise HTTPException(
                            status_code=status.HTTP_502_BAD_GATEWAY,
                            detail=f"Email delivery failed via SendGrid: {resp.text}"
                        )
                    logger.info(f"Verification email successfully dispatched to {masked_dest} via SendGrid")
                    return {"provider": "sendgrid", "status": "sent"}
            except httpx.RequestError as e:
                logger.error(f"Network error contacting SendGrid: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Network error while delivering verification email. Please try again."
                )

        # 3. SMTP Provider
        elif provider == "smtp":
            if not settings.SMTP_HOST:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="SMTP server host (SMTP_HOST) is not configured."
                )
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = settings.EMAIL_FROM_ADDRESS
            msg["To"] = to_email
            msg.attach(MIMEText(text_content, "plain"))
            msg.attach(MIMEText(html_content, "html"))

            try:
                server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10)
                if settings.SMTP_USE_TLS:
                    server.starttls()
                if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                server.sendmail(settings.EMAIL_FROM_ADDRESS, [to_email], msg.as_string())
                server.quit()
                logger.info(f"Verification email dispatched to {masked_dest} via SMTP")
                return {"provider": "smtp", "status": "sent"}
            except Exception as e:
                logger.error(f"SMTP delivery error: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"SMTP delivery failed: {str(e)}"
                )

        # 4. Development / Testing Console Mode
        elif provider == "console":
            if settings.ENVIRONMENT == "production":
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Console email provider is strictly forbidden in production. Please configure Resend, SendGrid, or SMTP."
                )
            # In testing/dev, log clear dispatch notification with OTP
            logger.info(f"[DEV CONSOLE EMAIL] Verification challenge created for destination: {masked_dest} (Purpose: {purpose})")
            logger.info(f"[DEV CONSOLE EMAIL] ---> 6-Digit OTP for {to_email}: [{code}] <--- (Valid for {settings.AUTH_CODE_TTL_SECONDS // 60} mins)")
            return {"provider": "console", "status": "sent", "destination": masked_dest}

        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Unsupported EMAIL_PROVIDER '{settings.EMAIL_PROVIDER}' configured."
            )

    @classmethod
    async def send_sms(cls, to_phone: str, code: str, purpose: str) -> Dict[str, Any]:
        """
        Deliver verification code to normalized E.164 phone number using configured SMS provider.
        """
        normalized_phone = normalize_phone_number(to_phone)
        masked_phone = mask_identifier(normalized_phone)
        provider = (settings.SMS_PROVIDER or "console").lower()

        message_body = f"GuardianMail AI code: {code}. Valid for {settings.AUTH_CODE_TTL_SECONDS // 60} mins. Never share your security code."

        # 1. Twilio SMS
        if provider == "twilio":
            if not settings.TWILIO_ACCOUNT_SID or not settings.TWILIO_AUTH_TOKEN or not settings.TWILIO_FROM_NUMBER:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Twilio SMS credentials (TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER) are not configured."
                )
            url = f"https://api.twilio.com/2010-04-01/Accounts/{settings.TWILIO_ACCOUNT_SID}/Messages.json"
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(
                        url,
                        auth=(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN),
                        data={
                            "From": settings.TWILIO_FROM_NUMBER,
                            "To": normalized_phone,
                            "Body": message_body
                        }
                    )
                    if resp.status_code not in (200, 201):
                        logger.error(f"Twilio SMS error: {resp.status_code} - {resp.text}")
                        raise HTTPException(
                            status_code=status.HTTP_502_BAD_GATEWAY,
                            detail=f"SMS delivery failed via Twilio: {resp.text}"
                        )
                    res_json = resp.json()
                    logger.info(f"Verification SMS successfully sent to {masked_phone} via Twilio")
                    return {"provider": "twilio", "status": "sent", "sid": res_json.get("sid")}
            except httpx.RequestError as e:
                logger.error(f"Network error contacting Twilio: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Network error while delivering SMS. Please try again."
                )

        # 2. Twilio Verify Service
        elif provider == "twilio_verify":
            if not settings.TWILIO_ACCOUNT_SID or not settings.TWILIO_AUTH_TOKEN or not settings.TWILIO_VERIFY_SERVICE_SID:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Twilio Verify credentials (TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_VERIFY_SERVICE_SID) are not configured."
                )
            url = f"https://verify.twilio.com/v2/Services/{settings.TWILIO_VERIFY_SERVICE_SID}/Verifications"
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(
                        url,
                        auth=(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN),
                        data={
                            "To": normalized_phone,
                            "Channel": "sms"
                        }
                    )
                    if resp.status_code not in (200, 201):
                        logger.error(f"Twilio Verify error: {resp.status_code} - {resp.text}")
                        raise HTTPException(
                            status_code=status.HTTP_502_BAD_GATEWAY,
                            detail=f"Twilio Verify delivery failed: {resp.text}"
                        )
                    res_json = resp.json()
                    logger.info(f"Verification challenge initiated for {masked_phone} via Twilio Verify")
                    return {"provider": "twilio_verify", "status": "sent", "sid": res_json.get("sid")}
            except httpx.RequestError as e:
                logger.error(f"Network error contacting Twilio Verify: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Network error while initiating SMS verification."
                )

        # 3. Development / Testing Console Mode
        elif provider == "console":
            if settings.ENVIRONMENT == "production":
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Console SMS provider is strictly forbidden in production. Please configure Twilio or Twilio Verify."
                )
            logger.info(f"[DEV CONSOLE SMS] SMS challenge created for destination: {masked_phone} (Purpose: {purpose})")
            return {"provider": "console", "status": "sent", "destination": masked_phone}

        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Unsupported SMS_PROVIDER '{settings.SMS_PROVIDER}' configured."
            )
