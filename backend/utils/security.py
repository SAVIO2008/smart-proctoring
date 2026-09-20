import secrets
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from backend.config.settings import settings
from backend.config.db import get_users_col

security_bearer = HTTPBearer(auto_error=False)

# In-memory revocation registry shared per-process. Session lifecycle helpers live in
# services/session_store.py and write to persistent storage so revocation survives restarts.
_revocation_registry: Dict[str, Any] = {"revoked": set()}


def _get_revocation_store() -> Dict[str, Any]:
    """Merge the persistent session store with the in-process cache."""
    from backend.services.session_store import session_store
    return {"revoked": session_store.get_revoked_jtis()}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = _utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    # A globally-unique token id enables logout/session revocation.
    to_encode.setdefault("jti", secrets.token_urlsafe(16))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except Exception:
        return None

async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)) -> Dict[str, Any]:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials not provided",
            headers={"WWW-Authenticate": "Bearer"}
        )
    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    user_id = payload["sub"]
    users_col = get_users_col()
    user = users_col.find_one({"_id": user_id})
    # Fallback: if _id lookup fails (e.g. ObjectId vs string mismatch for
    # users created before the string-_id fix), try the email from the JWT.
    if not user and "email" in payload:
        user = users_col.find_one({"email": payload["email"]})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token no longer exists",
            headers={"WWW-Authenticate": "Bearer"}
        )
    # Enforce server-side session revocation (logout) and token rotation.
    token_stores = _get_revocation_store()
    if payload.get("jti") in token_stores["revoked"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user

async def get_current_admin(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access restricted to administrative accounts"
        )
    return current_user

async def get_current_professor(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Allows professors and administrators to access professor-scoped routes."""
    if current_user.get("role") not in ("professor", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access restricted to professor and administrative accounts"
        )
    return current_user
