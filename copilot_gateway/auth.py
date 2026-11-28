"""Authentication and session management module using Argon2id and server-side sessions."""

from __future__ import annotations

import hashlib
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from dotenv import load_dotenv
from fastapi import Cookie, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import select

from .database import SessionRecord, UserRecord, get_session, now_iso

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env", override=False)

# Argon2id password hasher
_ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,  # 64 MiB
    parallelism=1,
    hash_len=32,
    salt_len=16,
)

COOKIE_NAME = "reposentinel_session"
SESSION_LIFETIME_DAYS = int(os.getenv("SESSION_LIFETIME_DAYS", "7"))
# Use Secure cookies if on HTTPS or explicitly configured
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() in ("true", "1")

# In-memory login attempt rate limiter: key -> list of timestamp floats
_FAILED_LOGINS: dict[str, list[float]] = {}
_MAX_FAILED_ATTEMPTS = 5
_LOCKOUT_SECONDS = 900  # 15 minutes


def hash_password(password: str) -> str:
    """Hash password using Argon2id."""
    return _ph.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against Argon2id hash."""
    try:
        return _ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, Exception):  # noqa: BLE001
        return False


def hash_token(token: str) -> str:
    """Hash session token with SHA-256 before database storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def check_rate_limit(identifier: str) -> None:
    """Check if identifier is rate limited for login attempts."""
    now = datetime.now(UTC).timestamp()
    attempts = _FAILED_LOGINS.get(identifier, [])
    # Filter attempts within lockout window
    recent = [t for t in attempts if now - t < _LOCKOUT_SECONDS]
    _FAILED_LOGINS[identifier] = recent
    if len(recent) >= _MAX_FAILED_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again after 15 minutes.",
        )


def record_failed_login(identifier: str) -> None:
    now = datetime.now(UTC).timestamp()
    attempts = _FAILED_LOGINS.setdefault(identifier, [])
    attempts.append(now)


def clear_failed_logins(identifier: str) -> None:
    _FAILED_LOGINS.pop(identifier, None)


def create_user_session(
    user_id: int,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, SessionRecord]:
    """Generate an unpredictable 32-byte session token, store its hash, and return raw token."""
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_token(raw_token)
    now = datetime.now(UTC)
    expires = now + timedelta(days=SESSION_LIFETIME_DAYS)

    session_record = SessionRecord(
        session_token_hash=token_hash,
        user_id=user_id,
        created_at=now.isoformat(),
        expires_at=expires.isoformat(),
        ip_address=ip_address,
        user_agent=user_agent[:300] if user_agent else None,
    )
    with get_session() as db:
        db.add(session_record)
        # Update user's last login
        user = db.get(UserRecord, user_id)
        if user:
            user.last_login_at = now_iso()
        db.commit()
        db.refresh(session_record)

    return raw_token, session_record


def set_session_cookie(response: Response, raw_token: str) -> None:
    """Set hardened HTTP-only SameSite cookie."""
    max_age = SESSION_LIFETIME_DAYS * 86400
    response.set_cookie(
        key=COOKIE_NAME,
        value=raw_token,
        max_age=max_age,
        expires=max_age,
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    """Remove session cookie."""
    response.delete_cookie(
        key=COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
    )


def revoke_session(raw_token: str) -> None:
    """Delete server-side session."""
    token_hash = hash_token(raw_token)
    with get_session() as db:
        sess = db.scalar(
            select(SessionRecord).where(SessionRecord.session_token_hash == token_hash)
        )
        if sess:
            db.delete(sess)
            db.commit()


def get_user_from_token(raw_token: str) -> UserRecord | None:
    """Retrieve active user from raw session token."""
    if not raw_token:
        return None
    token_hash = hash_token(raw_token)
    now_str = datetime.now(UTC).isoformat()

    with get_session() as db:
        sess = db.scalar(
            select(SessionRecord).where(
                SessionRecord.session_token_hash == token_hash,
                SessionRecord.expires_at > now_str,
            )
        )
        if not sess:
            return None
        return db.get(UserRecord, sess.user_id)


def get_token_from_request(
    request: Request,
    cookie_token: str | None = Cookie(default=None, alias=COOKIE_NAME),
    auth_header: str | None = Header(default=None, alias="Authorization"),
) -> str | None:
    """Extract session token from cookie or Authorization Bearer header."""
    if cookie_token:
        return cookie_token
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1].strip()
    return None


async def get_current_user_optional(
    request: Request,
    token: str | None = Depends(get_token_from_request),
) -> UserRecord | None:
    """Optional user dependency — returns None if unauthenticated."""
    if not token:
        return None
    return get_user_from_token(token)


async def get_current_user(
    user: UserRecord | None = Depends(get_current_user_optional),  # noqa: B008
) -> UserRecord:
    """Strict user dependency — raises 401 if unauthenticated."""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
