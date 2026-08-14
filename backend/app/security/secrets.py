import base64
import hashlib
from cryptography.fernet import Fernet
from app.config.settings import settings

class SecretManager:
    """Enterprise encryption service wrapper for secure storage of Client Secrets."""
    
    def __init__(self, key: str = settings.SECRET_KEY):
        # Fernet keys must be 32 bytes and base64 encoded
        h = hashlib.sha256(key.encode()).digest()
        self.fernet = Fernet(base64.urlsafe_b64encode(h))

    def encrypt(self, plain_text: str) -> str:
        """Encrypt plain text to secure cipher text."""
        if not plain_text:
            return ""
        return self.fernet.encrypt(plain_text.encode()).decode()

    def decrypt(self, cipher_text: str) -> str:
        """Decrypt cipher text to plain text."""
        if not cipher_text:
            return ""
        try:
            return self.fernet.decrypt(cipher_text.encode()).decode()
        except Exception:
            return cipher_text # fallback if not encrypted

secrets_manager = SecretManager()
