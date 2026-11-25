"""Configuration for the RepoSentinel GitHub FastAPI service."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVICE_DIR = Path(__file__).resolve().parent

load_dotenv(PROJECT_ROOT / ".env", override=False)


@dataclass(frozen=True)
class GitHubServiceSettings:
    """Runtime settings for github_service loaded from environment variables."""

    host: str = os.getenv("GITHUB_SERVICE_HOST", "127.0.0.1")
    port: int = int(os.getenv("GITHUB_SERVICE_PORT", "8001"))
    github_api_base: str = os.getenv(
        "GITHUB_API_BASE", "https://api.github.com"
    ).rstrip("/")
    github_token: str | None = os.getenv("GITHUB_TOKEN") or None
    request_timeout_seconds: float = float(os.getenv("GITHUB_TIMEOUT_SECONDS", "20.0"))
    cache_ttl_seconds: int = int(os.getenv("GITHUB_CACHE_TTL_SECONDS", "300"))
    cache_db_path: Path = Path(
        os.getenv("GITHUB_CACHE_DB_PATH", str(SERVICE_DIR / "github_cache.db"))
    )


def get_settings() -> GitHubServiceSettings:
    """Return fresh settings reading the current process environment."""
    load_dotenv(PROJECT_ROOT / ".env", override=False)
    return GitHubServiceSettings(
        host=os.getenv("GITHUB_SERVICE_HOST", "127.0.0.1"),
        port=int(os.getenv("GITHUB_SERVICE_PORT", "8001")),
        github_api_base=os.getenv("GITHUB_API_BASE", "https://api.github.com").rstrip(
            "/"
        ),
        github_token=os.getenv("GITHUB_TOKEN") or None,
        request_timeout_seconds=float(os.getenv("GITHUB_TIMEOUT_SECONDS", "20.0")),
        cache_ttl_seconds=int(os.getenv("GITHUB_CACHE_TTL_SECONDS", "300")),
        cache_db_path=Path(
            os.getenv("GITHUB_CACHE_DB_PATH", str(SERVICE_DIR / "github_cache.db"))
        ),
    )
