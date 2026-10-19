import html
import os
from datetime import datetime, timedelta, timezone
import bcrypt
import jwt

SECRET_KEY = os.getenv("JWT_SECRET", "hdu-is-lab-secure-jwt-secret-key-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def hash_password(password: str) -> str:
    """Hash password using bcrypt with automatic salt generation."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against stored bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Issue a signed JWT token with expiration and issue time."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"iat": now, "exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode and verify JWT signature and expiration."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def sanitize_xss(text: str) -> str:
    """Escape HTML characters to prevent Cross-Site Scripting (XSS)."""
    return html.escape(text.strip(), quote=True)
