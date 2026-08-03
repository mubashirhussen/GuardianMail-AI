import bcrypt
import logging

logger = logging.getLogger(__name__)

def hash_password(password: str) -> str:
    """Hash a plain text password using bcrypt algorithm directly (bypassing passlib bugs)."""
    try:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed.decode("utf-8")
    except Exception as e:
        logger.error(f"Failed to hash password: {str(e)}")
        raise RuntimeError("Password secure hashing operation failed.") from e

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain text password against its matching hashed representation."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception as e:
        logger.error(f"Failed to verify password: {str(e)}")
        return False
