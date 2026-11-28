"""pytest configuration, fixtures, and markers."""

import asyncio
import os
import sys

import pytest

# Skip spawning MCP stdio subprocesses during tests (they require live services)
os.environ.setdefault("SKIP_MCP_STARTUP", "1")

# Windows: force SelectorEventLoop so anyio doesn't hang on socket.socketpair()
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "live_api: test requires real network access to external APIs"
    )
    config.addinivalue_line("markers", "requires_groq: test requires GROQ_API_KEY")
    config.addinivalue_line("markers", "requires_gemini: test requires GEMINI_API_KEY")
    config.addinivalue_line("markers", "requires_tavily: test requires TAVILY_API_KEY")
    config.addinivalue_line(
        "markers", "mcp_integration: test requires both MCP servers running"
    )


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def tmp_db(tmp_path):
    """Isolated SQLite database for each test — never touches the production DB."""
    db_path = str(tmp_path / "test_reposentinel.db")
    os.environ["GATEWAY_DB_PATH"] = db_path
    os.environ["GITHUB_CACHE_DB_PATH"] = str(tmp_path / "test_github_cache.db")
    os.environ["OSV_CACHE_DB_PATH"] = str(tmp_path / "test_osv_cache.db")
    yield db_path


@pytest.fixture(scope="session")
def has_github_token():
    return bool(os.getenv("GITHUB_TOKEN"))


@pytest.fixture(scope="session")
def has_groq():
    return bool(os.getenv("GROQ_API_KEY"))


@pytest.fixture(scope="session")
def has_gemini():
    return bool(os.getenv("GEMINI_API_KEY"))


@pytest.fixture(scope="session")
def has_tavily():
    return bool(os.getenv("TAVILY_API_KEY"))
