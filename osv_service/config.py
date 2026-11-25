"""Configuration for the RepoSentinel OSV Vulnerability FastAPI service."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVICE_DIR = Path(__file__).resolve().parent

load_dotenv(PROJECT_ROOT / ".env", override=False)


@dataclass(frozen=True)
class OSVServiceSettings:
    """Runtime settings for osv_service loaded from environment variables."""

    host: str = os.getenv("OSV_SERVICE_HOST", "127.0.0.1")
    port: int = int(os.getenv("OSV_SERVICE_PORT", "8002"))
    osv_api_base: str = os.getenv("OSV_API_BASE", "https://api.osv.dev").rstrip("/")
    pypi_api_base: str = os.getenv("PYPI_API_BASE", "https://pypi.org/pypi").rstrip("/")
    request_timeout_seconds: float = float(os.getenv("OSV_TIMEOUT_SECONDS", "25.0"))
    cache_ttl_seconds: int = int(os.getenv("OSV_CACHE_TTL_SECONDS", "300"))
    cache_db_path: Path = Path(
        os.getenv("OSV_CACHE_DB_PATH", str(SERVICE_DIR / "osv_cache.db"))
    )


def get_settings() -> OSVServiceSettings:
    """Return fresh settings reading the current process environment."""
    load_dotenv(PROJECT_ROOT / ".env", override=False)
    return OSVServiceSettings(
        host=os.getenv("OSV_SERVICE_HOST", "127.0.0.1"),
        port=int(os.getenv("OSV_SERVICE_PORT", "8002")),
        osv_api_base=os.getenv("OSV_API_BASE", "https://api.osv.dev").rstrip("/"),
        pypi_api_base=os.getenv("PYPI_API_BASE", "https://pypi.org/pypi").rstrip("/"),
        request_timeout_seconds=float(os.getenv("OSV_TIMEOUT_SECONDS", "25.0")),
        cache_ttl_seconds=int(os.getenv("OSV_CACHE_TTL_SECONDS", "300")),
        cache_db_path=Path(
            os.getenv("OSV_CACHE_DB_PATH", str(SERVICE_DIR / "osv_cache.db"))
        ),
    )
