"""Live demo extension router: real PyPI latest published release endpoint.

Initially kept outside osv_service/main.py so Synapse Auto only discovers it
after activate_registry_demo.ps1 wires it into osv_service and runs
`synapse build --auto --local --all-endpoints --discover`.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from osv_service.package_registry import (
    PyPIAPIError,
    PyPILatestReleaseResponse,
    fetch_pypi_latest_release,
)

router = APIRouter(tags=["PyPI Registry"])


@router.get(
    "/registry/pypi/{package_name}/latest-release",
    response_model=PyPILatestReleaseResponse,
    summary="Get the latest published release for a PyPI package",
)
async def get_pypi_latest_release(package_name: str) -> PyPILatestReleaseResponse:
    """Query https://pypi.org/pypi/{package_name}/json for the real latest published version."""
    try:
        return await fetch_pypi_latest_release(package_name)
    except PyPIAPIError as err:
        raise HTTPException(
            status_code=err.status_code,
            detail={"error": err.message, "source_url": err.source_url},
        ) from err
