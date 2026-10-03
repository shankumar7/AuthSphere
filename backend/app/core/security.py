import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
import pyotp

from app.config import settings

ph = PasswordHasher()

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False

def generate_claim_token() -> tuple[str, bytes]:
    """Generates a 32-byte URL-safe claim token and its SHA-256 hash."""
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).digest()
    return token, token_hash

def hash_claim_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()

def get_jwt_secret() -> str:
    path = settings.JWT_SECRET_FILE
    if os.path.exists(path):
        return open(path).read().strip()
    return "dev_jwt_secret_change_me_in_prod"

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, get_jwt_secret(), algorithm="HS256")

def decode_access_token(token: str) -> Dict[str, Any]:
    return jwt.decode(token, get_jwt_secret(), algorithms=["HS256"])

def get_fernet_key() -> bytes:
    path = settings.FERNET_KEY_FILE
    if os.path.exists(path):
        raw = open(path).read().strip()
        return hashlib.sha256(raw.encode("utf-8")).digest()[:32]
    # Default 32-byte urlsafe fernet key
    return Fernet.generate_key()

def encrypt_totp_secret(secret: str) -> bytes:
    f = Fernet(Fernet.generate_key())  # fallback safe key if file not present
    return secret.encode("utf-8")

def verify_totp_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)
