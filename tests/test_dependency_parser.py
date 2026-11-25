"""Tests for dependency manifest parsing (no network required)."""

from __future__ import annotations

from github_service.dependency_parser import (
    merge_dependency_records,
    parse_lockfile_toml,
    parse_pyproject_toml,
    parse_requirements_txt,
)

FAKE_SOURCE_URL = "https://api.github.com/repos/test/test/contents/requirements.txt"


class TestRequirementsTxtParser:
    def test_pinned_version_is_resolved(self):
        content = "requests==2.28.0\n"
        recs = parse_requirements_txt(content, "requirements.txt", FAKE_SOURCE_URL)
        assert len(recs) == 1
        r = recs[0]
        assert r.package_name == "requests"
        assert r.installed_version == "2.28.0"
        assert r.is_resolved is True
        assert r.resolution_status == "pinned"

    def test_range_specifier_is_unresolved(self):
        content = "flask>=2.0,<3.0\n"
        recs = parse_requirements_txt(content, "requirements.txt", FAKE_SOURCE_URL)
        assert len(recs) == 1
        r = recs[0]
        assert r.is_resolved is False
        assert r.installed_version is None
        assert r.resolution_status == "unresolved"

    def test_tilde_specifier_is_unresolved(self):
        content = "numpy~=1.24.0\n"
        recs = parse_requirements_txt(content, "requirements.txt", FAKE_SOURCE_URL)
        assert recs[0].is_resolved is False
        assert recs[0].installed_version is None

    def test_comment_lines_skipped(self):
        content = "# This is a comment\nrequests==2.28.0\n"
        recs = parse_requirements_txt(content, "requirements.txt", FAKE_SOURCE_URL)
        assert len(recs) == 1

    def test_blank_lines_skipped(self):
        content = "\n\nrequests==2.28.0\n\n"
        recs = parse_requirements_txt(content, "requirements.txt", FAKE_SOURCE_URL)
        assert len(recs) == 1

    def test_hash_stripped_correctly(self):
        content = "cryptography==41.0.3 --hash=sha256:abcdef1234\n"
        recs = parse_requirements_txt(content, "requirements.txt", FAKE_SOURCE_URL)
        assert len(recs) == 1
        assert recs[0].installed_version == "41.0.3"
        assert recs[0].is_resolved is True

    def test_extras_stripped(self):
        content = "fastapi[standard]==0.111.0\n"
        recs = parse_requirements_txt(content, "requirements.txt", FAKE_SOURCE_URL)
        assert len(recs) == 1
        assert recs[0].package_name == "fastapi"
        assert recs[0].installed_version == "0.111.0"

    def test_no_version_is_unresolved(self):
        content = "requests\n"
        recs = parse_requirements_txt(content, "requirements.txt", FAKE_SOURCE_URL)
        assert recs[0].is_resolved is False

    def test_option_lines_skipped(self):
        content = "--index-url https://pypi.org/simple\nrequests==2.28.0\n"
        recs = parse_requirements_txt(content, "requirements.txt", FAKE_SOURCE_URL)
        assert len(recs) == 1


class TestPyprojectTomlParser:
    def test_pep621_exact_version(self):
        content = """
[project]
dependencies = ["requests==2.28.0"]
"""
        recs = parse_pyproject_toml(content, "pyproject.toml", FAKE_SOURCE_URL)
        assert any(r.package_name == "requests" and r.is_resolved for r in recs)

    def test_pep621_range_is_unresolved(self):
        content = """
[project]
dependencies = ["flask>=2.0,<3.0"]
"""
        recs = parse_pyproject_toml(content, "pyproject.toml", FAKE_SOURCE_URL)
        assert any(r.package_name == "flask" and not r.is_resolved for r in recs)

    def test_poetry_exact_version(self):
        content = """
[tool.poetry.dependencies]
requests = "2.28.0"
"""
        recs = parse_pyproject_toml(content, "pyproject.toml", FAKE_SOURCE_URL)
        assert any(
            r.package_name == "requests"
            and r.is_resolved
            and r.installed_version == "2.28.0"
            for r in recs
        )

    def test_poetry_caret_is_unresolved(self):
        content = """
[tool.poetry.dependencies]
flask = "^2.0"
"""
        recs = parse_pyproject_toml(content, "pyproject.toml", FAKE_SOURCE_URL)
        assert any(r.package_name == "flask" and not r.is_resolved for r in recs)

    def test_python_dependency_skipped(self):
        content = """
[tool.poetry.dependencies]
python = "^3.11"
requests = "2.28.0"
"""
        recs = parse_pyproject_toml(content, "pyproject.toml", FAKE_SOURCE_URL)
        assert not any(r.package_name.lower() == "python" for r in recs)


class TestLockfileParser:
    def test_uv_lock_exact_version(self):
        content = """
[[package]]
name = "requests"
version = "2.28.0"
"""
        recs = parse_lockfile_toml(content, "uv.lock", "uv.lock", FAKE_SOURCE_URL)
        assert len(recs) == 1
        assert recs[0].installed_version == "2.28.0"
        assert recs[0].is_resolved is True

    def test_poetry_lock_exact_version(self):
        content = """
[[package]]
name = "cryptography"
version = "41.0.3"
"""
        recs = parse_lockfile_toml(
            content, "poetry.lock", "poetry.lock", FAKE_SOURCE_URL
        )
        assert any(
            r.package_name == "cryptography" and r.installed_version == "41.0.3"
            for r in recs
        )

    def test_lockfile_multiple_packages(self):
        content = """
[[package]]
name = "requests"
version = "2.28.0"

[[package]]
name = "flask"
version = "3.0.0"
"""
        recs = parse_lockfile_toml(content, "uv.lock", "uv.lock", FAKE_SOURCE_URL)
        assert len(recs) == 2
        names = {r.package_name for r in recs}
        assert "requests" in names
        assert "flask" in names


class TestMergeDependencyRecords:
    def test_lockfile_wins_over_requirements(self):
        from github_service.dependency_parser import (
            merge_dependency_records,
            parse_lockfile_toml,
            parse_requirements_txt,
        )

        txt_recs = parse_requirements_txt(
            "requests>=2.0\n", "requirements.txt", FAKE_SOURCE_URL
        )
        lock_recs = parse_lockfile_toml(
            "[[package]]\nname = 'requests'\nversion = '2.28.0'\n",
            "uv.lock",
            "uv.lock",
            FAKE_SOURCE_URL,
        )
        merged = merge_dependency_records(txt_recs + lock_recs)
        req_rec = next(r for r in merged if r.normalized_name == "requests")
        assert req_rec.is_resolved is True
        assert req_rec.installed_version == "2.28.0"

    def test_deduplication_keeps_one_per_package(self):
        content = "requests==2.28.0\nrequests==2.28.0\n"
        recs = parse_requirements_txt(content, "requirements.txt", FAKE_SOURCE_URL)
        merged = merge_dependency_records(recs)
        req_recs = [r for r in merged if r.normalized_name == "requests"]
        assert len(req_recs) == 1
