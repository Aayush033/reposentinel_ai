"""Real PyPI JSON registry client helper (exposed live via demo_extensions during Demo 3)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
from pydantic import BaseModel, Field

from .config import get_settings


class PyPIAPIError(Exception):
    """Raised when pypi.org returns an error or cannot be reached."""

    def __init__(self, status_code: int, message: str, source_url: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.source_url = source_url


class PyPILatestReleaseResponse(BaseModel):
    """Genuine PyPI latest published release metadata."""

    package_name: str
    latest_version: str
    summary: str | None = None
    author: str | None = None
    license: str | None = None
    requires_python: str | None = None
    upload_time_iso: str | None = None
    yanked: bool = False
    project_url: str
    source_url: str
    http_status: int
    fetched_at: str
    note: str = Field(
        default="Latest published PyPI version retrieved live; compatibility with project constraints is not automatically guaranteed."
    )


async def fetch_pypi_latest_release(package_name: str) -> PyPILatestReleaseResponse:
    """Query https://pypi.org/pypi/{package_name}/json for the real latest published version."""
    settings = get_settings()
    clean_name = package_name.strip()
    url = f"{settings.pypi_api_base}/{clean_name}/json"

    try:
        async with httpx.AsyncClient(
            timeout=settings.request_timeout_seconds
        ) as client:
            response = await client.get(
                url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "RepoSentinel-AI-RegistryClient/1.0",
                },
            )
    except httpx.TimeoutException as exc:
        raise PyPIAPIError(
            status_code=504,
            message=f"PyPI registry request timed out for '{clean_name}': {exc}",
            source_url=url,
        ) from exc
    except httpx.HTTPError as exc:
        raise PyPIAPIError(
            status_code=502,
            message=f"Network error contacting PyPI registry for '{clean_name}': {exc}",
            source_url=url,
        ) from exc

    fetched_at = datetime.now(UTC).isoformat()
    if response.status_code == 404:
        raise PyPIAPIError(
            status_code=404,
            message=f"Package '{clean_name}' was not found on PyPI.",
            source_url=url,
        )
    if response.status_code >= 400:
        raise PyPIAPIError(
            status_code=response.status_code,
            message=f"PyPI registry returned HTTP {response.status_code} for '{clean_name}': {response.text[:250]}",
            source_url=url,
        )

    payload: dict[str, Any] = response.json()
    info = payload.get("info") or {}
    latest_version = str(info.get("version") or "").strip()
    if not latest_version:
        raise PyPIAPIError(
            status_code=502,
            message=f"PyPI JSON response for '{clean_name}' did not include info.version.",
            source_url=url,
        )

    releases = payload.get("releases") or {}
    latest_files = releases.get(latest_version) or []
    upload_time_iso = None
    yanked = False
    if isinstance(latest_files, list) and latest_files:
        first_file = latest_files[0]
        if isinstance(first_file, dict):
            upload_time_iso = first_file.get("upload_time_iso_8601")
            yanked = bool(first_file.get("yanked", False))

    return PyPILatestReleaseResponse(
        package_name=str(info.get("name") or clean_name),
        latest_version=latest_version,
        summary=info.get("summary"),
        author=info.get("author") or info.get("maintainer"),
        license=info.get("license"),
        requires_python=info.get("requires_python"),
        upload_time_iso=upload_time_iso,
        yanked=yanked,
        project_url=str(
            info.get("package_url") or f"https://pypi.org/project/{clean_name}/"
        ),
        source_url=url,
        http_status=response.status_code,
        fetched_at=fetched_at,
    )
