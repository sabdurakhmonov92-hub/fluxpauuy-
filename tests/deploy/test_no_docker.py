"""Permanent Meta-Guard: Zero-Docker Architecture Enforcement.

Guarantees that Dockerfile, docker-compose configurations, and container execution
primitives never return to this codebase. Deployment is strictly native systemd + UDS.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOY_DIR = REPO_ROOT / "deploy"
MAKEFILE_PATH = REPO_ROOT / "Makefile"

VIOLATION_MSG = "ARCHITECTURE VIOLATION: Docker is banned (native systemd + UDS). See docs/dev.md."

BANNED_PATTERNS = [
    "dockerfile",
    "dockerfile.*",
    "*.dockerfile",
    "docker-compose*.yml",
    "docker-compose*.yaml",
]


def test_no_docker_files_in_repo() -> None:
    """Walk entire repository tree; assert zero Docker-related files exist."""
    # Ignore .git, .venv, .pytest_cache
    ignored_dirs = {".git", ".venv", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules"}

    offending_files: list[Path] = []
    for p in REPO_ROOT.rglob("*"):
        if any(ignored in p.parts for ignored in ignored_dirs):
            continue
        if not p.is_file():
            continue

        lower_name = p.name.lower()
        for pat in BANNED_PATTERNS:
            if fnmatch.fnmatch(lower_name, pat):
                offending_files.append(p)
                break

    assert not offending_files, f"{VIOLATION_MSG} Found offending files: {offending_files}"


def test_no_docker_strings_in_deploy_and_makefile() -> None:
    """Assert no 'FROM python:' or 'docker run' strings in deploy/ and Makefile."""
    files_to_check: list[Path] = []

    if MAKEFILE_PATH.is_file():
        files_to_check.append(MAKEFILE_PATH)

    for p in DEPLOY_DIR.rglob("*"):
        if p.is_file():
            files_to_check.append(p)

    banned_substrings = ["from python:", "docker run"]

    for file_path in files_to_check:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue

        for banned in banned_substrings:
            rel_path = file_path.relative_to(REPO_ROOT)
            assert banned not in content, (
                f"{VIOLATION_MSG} Found banned instruction '{banned}' in {rel_path}"
            )
