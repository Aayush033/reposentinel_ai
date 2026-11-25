"""Database models and engine for copilot_gateway (SQLAlchemy 2.x, SQLite)."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from sqlalchemy import (
    JSON,
    Boolean,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env", override=False)

_DB_PATH = Path(
    os.getenv("GATEWAY_DB_PATH", str(Path(__file__).parent / "reposentinel.db"))
)
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    f"sqlite:///{_DB_PATH}",
    connect_args={"check_same_thread": False},
    echo=False,
)


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    """Persists a completed or errored cross-system security scan."""

    __tablename__ = "scan_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    repo: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    started_at: Mapped[str] = mapped_column(String(50), nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String(50), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="running")
    total_dependencies: Mapped[int] = mapped_column(Integer, default=0)
    resolved_count: Mapped[int] = mapped_column(Integer, default=0)
    unresolved_count: Mapped[int] = mapped_column(Integer, default=0)
    vulnerable_packages_count: Mapped[int] = mapped_column(Integer, default=0)
    total_vulnerabilities: Mapped[int] = mapped_column(Integer, default=0)
    scan_summary: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class ToolCallAuditRecord(Base):
    """Audit log for every MCP tool call made during agent execution."""

    __tablename__ = "tool_call_audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    scan_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    server_name: Mapped[str] = mapped_column(String(100), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(200), nullable=False)
    arguments_json: Mapped[str] = mapped_column(Text, default="{}")
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    called_at: Mapped[str] = mapped_column(String(50), nullable=False)
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)


class ChatSession(Base):
    """Persists AI agent chat interactions."""

    __tablename__ = "chat_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    scan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    owner: Mapped[str | None] = mapped_column(String(200), nullable=True)
    repo: Mapped[str | None] = mapped_column(String(200), nullable=True)
    user_message: Mapped[str] = mapped_column(Text, nullable=False)
    agent_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    groq_model_used: Mapped[str | None] = mapped_column(String(200), nullable=True)
    gemini_model_used: Mapped[str | None] = mapped_column(String(200), nullable=True)
    tool_calls_count: Mapped[int] = mapped_column(Integer, default=0)
    iterations: Mapped[int] = mapped_column(Integer, default=0)
    total_duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    started_at: Mapped[str] = mapped_column(String(50), nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="running")
    execution_trace_json: Mapped[str | None] = mapped_column(Text, nullable=True)


def create_tables() -> None:
    Base.metadata.create_all(engine)


def get_session() -> Session:
    return Session(engine)


def now_iso() -> str:
    return datetime.now(UTC).isoformat()
