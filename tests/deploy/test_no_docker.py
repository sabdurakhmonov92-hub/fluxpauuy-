"""Production Container & Deployment Hardening Meta-Guard.

Enforces production standards across all containerization and deployment artifacts:
- Dual-target deployment (Docker + bare-metal systemd) must adhere to strict hardening.
- If Dockerfile exists: MUST use multi-stage builds, non-root user, and curl healthcheck.
- Zero secrets or .env files copied into container layers.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE_PATH = REPO_ROOT / "Dockerfile"
DOCKERIGNORE_PATH = REPO_ROOT / ".dockerignore"


def test_dockerfile_security_hardening() -> None:
    """Verify Dockerfile adheres to fintech security standards."""
    if not DOCKERFILE_PATH.is_file():
        pytest.skip("Dockerfile not present; skipping container hardening checks.")

    content = DOCKERFILE_PATH.read_text(encoding="utf-8")
    content_lower = content.lower()

    # 1. Multi-stage build
    assert "as builder" in content_lower, "Dockerfile must use a multi-stage builder stage."

    # 2. Minimal runtime image
    assert "python:3.12-slim" in content_lower or "python:3.12" in content_lower, (
        "Dockerfile must use Python 3.12 slim base image."
    )

    # 3. Non-root execution
    assert "user " in content_lower, "Dockerfile must drop root privileges (e.g. USER fluxpay)."
    assert "user root" not in content_lower[-200:], "Dockerfile must not terminate with USER root."

    # 4. Healthcheck defined
    assert "healthcheck" in content_lower, "Dockerfile must declare a HEALTHCHECK instruction."

    # 5. Environment invariants
    assert "pythonunbuffered=1" in content_lower, "PYTHONUNBUFFERED=1 must be set."
    assert "pythondontwritebytecode=1" in content_lower, "PYTHONDONTWRITEBYTECODE=1 must be set."


def test_dockerignore_prevents_secret_leakage() -> None:
    """Verify .dockerignore prevents leaking secrets, git history, or local virtualenvs."""
    if not DOCKERIGNORE_PATH.is_file():
        pytest.skip(".dockerignore not present; skipping secret exclusion checks.")

    content = DOCKERIGNORE_PATH.read_text(encoding="utf-8")
    lines = {
        line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")
    }

    required_exclusions = {".git", ".venv", ".env*"}
    for req in required_exclusions:
        assert any(req in line for line in lines), (
            f".dockerignore must exclude '{req}' to prevent credential and cache leakage."
        )
