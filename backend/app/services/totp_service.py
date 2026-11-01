"""
TOTP Authenticator Service for Google Authenticator & Microsoft Authenticator integration.
RFC 6238 compliant with QR code image generation and sliding window verification.
"""

import io
import base64
import logging
from typing import Tuple, Dict, Any, Optional
import pyotp
import qrcode

logger = logging.getLogger(__name__)

class TOTPService:
    """Manages Time-Based One-Time Password generation, QR code provisioning, and validation."""

    ISSUER_NAME = "MailGuard AI"

    @classmethod
    def generate_secret(cls) -> str:
        """Generate cryptographically secure base32 secret key."""
        return pyotp.random_base32()

    @classmethod
    def get_provisioning_details(cls, email: str, secret: Optional[str] = None) -> Dict[str, str]:
        """
        Generate provisioning URI and base64 PNG data URL for scanning in
        Microsoft Authenticator, Google Authenticator, or 1Password.
        """
        sec = secret or cls.generate_secret()
        totp = pyotp.TOTP(sec)
        uri = totp.provisioning_uri(name=email, issuer_name=cls.ISSUER_NAME)

        # Generate QR code image in memory
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=6,
            border=2,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#0f172a", back_color="#ffffff")

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_base64 = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("utf-8")

        return {
            "secret": sec,
            "otpauth_url": uri,
            "qr_code_url": qr_base64,
            "issuer": cls.ISSUER_NAME,
            "account": email
        }

    @classmethod
    def verify_code(cls, secret: str, code: str, valid_window: int = 1) -> bool:
        """
        Verify a 6-digit TOTP code against the secret key.
        valid_window=1 allows +-30 seconds of clock drift for mobile devices.
        """
        if not secret or not code:
            return False
        clean_code = str(code).strip().replace(" ", "").replace("-", "")
        if not clean_code.isdigit() or len(clean_code) != 6:
            return False

        try:
            totp = pyotp.TOTP(secret)
            return bool(totp.verify(clean_code, valid_window=valid_window))
        except Exception as e:
            logger.error(f"TOTP verification error: {str(e)}")
            return False
