"""Tests for user authentication, session security, and data isolation.

Tests the auth and database layers DIRECTLY without going through HTTP —
Starlette TestClient and httpx.AsyncClient both require socket.socketpair()
which the sandbox blocks on Windows. We test the same business logic by
calling the internal functions and SQLAlchemy models directly.
"""

from __future__ import annotations

import pytest
from sqlalchemy import delete, select

from copilot_gateway.auth import (
    create_user_session,
    hash_password,
    hash_token,
    verify_password,
)
from copilot_gateway.database import (
    ProjectRecord,
    SessionRecord,
    UserRecord,
    create_tables,
    get_session,
    now_iso,
)


@pytest.fixture(autouse=True)
def setup_tables(tmp_db):
    create_tables()
    with get_session() as db:
        db.execute(delete(SessionRecord))
        db.execute(delete(ProjectRecord))
        db.execute(delete(UserRecord))
        db.commit()
    yield


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


def test_argon2id_hash_format(tmp_db):
    """hash_password produces a proper Argon2id hash string."""
    h = hash_password("Password123!")
    assert h.startswith("$argon2id$")
    assert "Password123!" not in h


def test_argon2id_verify_correct(tmp_db):
    """verify_password returns True for the correct password."""
    h = hash_password("CorrectHorse99!")
    assert verify_password("CorrectHorse99!", h) is True


def test_argon2id_verify_wrong(tmp_db):
    """verify_password returns False for a wrong password."""
    h = hash_password("CorrectHorse99!")
    assert verify_password("WrongPassword!", h) is False


# ---------------------------------------------------------------------------
# User registration (DB level)
# ---------------------------------------------------------------------------


def test_user_registration_stores_argon2_hash(tmp_db):
    """Registering a user stores Argon2id hash — never plain text."""
    pwd_hash = hash_password("Password123!")
    with get_session() as db:
        user = UserRecord(
            username="alice",
            email="alice@example.com",
            password_hash=pwd_hash,
            full_name="Alice Security",
            created_at=now_iso(),
            last_login_at=now_iso(),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        assert user.id is not None
        assert user.username == "alice"
        assert user.email == "alice@example.com"
        assert user.password_hash.startswith("$argon2id$")
        assert "Password123!" not in user.password_hash


def test_duplicate_username_rejected(tmp_db):
    """SQLAlchemy unique constraint prevents duplicate usernames."""
    from sqlalchemy.exc import IntegrityError

    pwd_hash = hash_password("Password123!")
    with get_session() as db:
        u1 = UserRecord(
            username="bob",
            email="bob@example.com",
            password_hash=pwd_hash,
            created_at=now_iso(),
            last_login_at=now_iso(),
        )
        db.add(u1)
        db.commit()

    with pytest.raises(IntegrityError), get_session() as db:
        u2 = UserRecord(
            username="bob",
            email="other@example.com",
            password_hash=pwd_hash,
            created_at=now_iso(),
            last_login_at=now_iso(),
        )
        db.add(u2)
        db.commit()


# ---------------------------------------------------------------------------
# Session tokens
# ---------------------------------------------------------------------------


def test_session_token_format_and_hashing(tmp_db):
    """Session tokens are 32-byte URL-safe strings; only their hash is stored."""
    pwd_hash = hash_password("SecurePassword99!")
    with get_session() as db:
        user = UserRecord(
            username="charlie",
            email="charlie@example.com",
            password_hash=pwd_hash,
            created_at=now_iso(),
            last_login_at=now_iso(),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        user_id = user.id

    raw_token, _session = create_user_session(user_id)

    # Raw token is long enough and URL-safe
    assert len(raw_token) >= 32
    assert all(
        c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_="
        for c in raw_token
    )

    # Stored hash is SHA-256 of the raw token — never the token itself
    expected_hash = hash_token(raw_token)
    with get_session() as db:
        srec = db.scalar(select(SessionRecord).where(SessionRecord.user_id == user_id))
        assert srec is not None
        assert srec.session_token_hash == expected_hash
        assert raw_token not in srec.session_token_hash


def test_session_revocation(tmp_db):
    """Revoking a session removes it from the database."""
    from copilot_gateway.auth import revoke_session

    pwd_hash = hash_password("RevokablePass1!")
    with get_session() as db:
        user = UserRecord(
            username="eve",
            email="eve@example.com",
            password_hash=pwd_hash,
            created_at=now_iso(),
            last_login_at=now_iso(),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        user_id = user.id

    raw_token, _ = create_user_session(user_id)
    token_hash = hash_token(raw_token)

    # Confirm session exists
    with get_session() as db:
        srec = db.scalar(
            select(SessionRecord).where(SessionRecord.session_token_hash == token_hash)
        )
        assert srec is not None

    # Revoke it
    revoke_session(raw_token)

    # Confirm session is gone
    with get_session() as db:
        srec_after = db.scalar(
            select(SessionRecord).where(SessionRecord.session_token_hash == token_hash)
        )
        assert srec_after is None


# ---------------------------------------------------------------------------
# User data isolation (DB level)
# ---------------------------------------------------------------------------


def test_user_data_isolation(tmp_db):
    """Projects for user A are not visible when querying for user B's projects."""
    pwd_hash = hash_password("Password123!")

    with get_session() as db:
        user_a = UserRecord(
            username="usera",
            email="a@test.com",
            password_hash=pwd_hash,
            created_at=now_iso(),
            last_login_at=now_iso(),
        )
        user_b = UserRecord(
            username="userb",
            email="b@test.com",
            password_hash=pwd_hash,
            created_at=now_iso(),
            last_login_at=now_iso(),
        )
        db.add(user_a)
        db.add(user_b)
        db.commit()
        db.refresh(user_a)
        db.refresh(user_b)
        user_a_id = user_a.id
        user_b_id = user_b.id

    # Insert a project for User A
    with get_session() as db:
        p_a = ProjectRecord(
            user_id=user_a_id,
            owner="usera-org",
            repo="private-repo",
            default_branch="main",
            created_at=now_iso(),
        )
        db.add(p_a)
        db.commit()

    # User B sees no projects
    with get_session() as db:
        b_projects = db.scalars(
            select(ProjectRecord).where(ProjectRecord.user_id == user_b_id)
        ).all()
        assert b_projects == []

    # User A sees their project
    with get_session() as db:
        a_projects = db.scalars(
            select(ProjectRecord).where(ProjectRecord.user_id == user_a_id)
        ).all()
        assert len(a_projects) == 1
        assert a_projects[0].repo == "private-repo"
