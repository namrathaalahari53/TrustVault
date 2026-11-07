import os
import re
import time
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from backend.app.core.config import settings

pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")
security_bearer = HTTPBearer(auto_error=False)

# In-memory rate limiting map: ip_or_email -> (attempts, lockout_until)
rate_limit_map: Dict[str, Dict[str, Any]] = {}

def check_login_rate_limit(key: str) -> bool:
    record = rate_limit_map.get(key.lower())
    if not record:
        return True
    if record.get("lockout_until", 0) > time.time():
        return False
    return True

def record_login_attempt(key: str, success: bool):
    k = key.lower()
    now = time.time()
    if success:
        rate_limit_map.pop(k, None)
        return

    record = rate_limit_map.get(k, {"attempts": 0, "lockout_until": 0})
    record["attempts"] += 1
    if record["attempts"] >= settings.LOGIN_RATE_LIMIT_ATTEMPTS:
        record["lockout_until"] = now + settings.LOGIN_LOCKOUT_SECONDS
    rate_limit_map[k] = record

def hash_password(password: str) -> str:
    # Use argon2 if available or salted sha512
    salt = os.urandom(16).hex()
    hashed = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()
    return f"{salt}:{hashed}"

def verify_password(plain_password: str, stored_hash: str) -> bool:
    try:
        parts = stored_hash.split(":")
        if len(parts) != 2:
            return False
        salt, expected_hash = parts
        calc_hash = hashlib.pbkdf2_hmac("sha512", plain_password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()
        return hmac.compare_digest(calc_hash, expected_hash)
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def sanitize_filename(filename: str) -> str:
    # Strip path separators, null bytes, and traversal components
    clean_name = os.path.basename(filename).replace("\0", "")
    clean_name = re.sub(r"[^a-zA-Z0-9._\- ]", "_", clean_name)
    return clean_name

def validate_magic_bytes(content: bytes, ext: str) -> tuple[bool, str]:
    ext = ext.lower()
    if len(content) > settings.MAX_FILE_SIZE_MB * 1024 * 1024:
        return False, "File exceeds maximum permitted file size."
    if len(content) == 0:
        return False, "File is empty."

    # PDF: %PDF- (25 50 44 46)
    if ext == ".pdf":
        if not content.startswith(b"%PDF"):
            return False, "Invalid signature: Missing PDF magic header."
        return True, ""

    # PNG: 89 50 4E 47
    if ext == ".png":
        if not (len(content) >= 8 and content[:4] == b"\x89PNG"):
            return False, "Invalid signature: Missing PNG magic header."
        return True, ""

    # JPG: FF D8 FF
    if ext in [".jpg", ".jpeg"]:
        if not (len(content) >= 3 and content[:3] == b"\xff\xd8\xff"):
            return False, "Invalid signature: Missing JPEG magic header."
        return True, ""

    # DOCX/XLSX: PK\x03\x04
    if ext in [".docx", ".xlsx"]:
        if not (len(content) >= 4 and content[:4] == b"PK\x03\x04"):
            return False, "Invalid signature: Missing Office OpenXML zip container."
        return True, ""

    # Plain text / CSV: No null bytes or binary execution tokens
    if ext in [".txt", ".csv"]:
        sample = content[:1024]
        if b"\x00" in sample:
            return False, "Binary or executable content found in text/csv file."
        return True, ""

    allowed_exts = [".pdf", ".doc", ".docx", ".txt", ".csv", ".xlsx", ".png", ".jpg", ".jpeg"]
    if ext not in allowed_exts:
        return False, f"File extension '{ext}' is not permitted."

    return True, ""
