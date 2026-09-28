"""Permanent Meta-Guard: Environment Contract & Settings Synchronization.

Guarantees:
1. 100% of Settings.model_fields exist in .env.example with FLX_ prefix.
2. Each field in .env.example is annotated with [REQUIRED] or [OPTIONAL default=...].
3. Top header contains Doppler instruction and 'NEVER commit .env'.
4. 100% of Settings.model_fields exist in Ansible /etc/fluxpay/env.template (if present).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from fluxpay.config import Settings

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
ENV_EXAMPLE_PATH = REPO_ROOT / ".env.example"
ANSIBLE_PLAYBOOK_PATH = REPO_ROOT / "deploy" / "ansible" / "playbook.yml"


def test_env_example_contains_all_settings_fields() -> None:
    """Assert all Settings model fields are present in .env.example with FLX_ prefix."""
    assert ENV_EXAMPLE_PATH.is_file(), f"Missing {ENV_EXAMPLE_PATH}"

    env_content = ENV_EXAMPLE_PATH.read_text(encoding="utf-8")

    all_fields = Settings.model_fields.keys()
    assert len(all_fields) >= 40, f"Expected >= 40 settings fields, got {len(all_fields)}"

    missing: list[str] = []
    for field_name in all_fields:
        expected_var = f"FLX_{field_name.upper()}"
        # Match as an assignment or commented variable
        if not re.search(rf"\b{expected_var}\b", env_content):
            missing.append(f"{field_name} ({expected_var})")

    assert not missing, (
        f".env.example is missing {len(missing)} fields from Settings:\n"
        + "\n".join(f"  - {m}" for m in missing)
    )


def test_env_example_header_and_annotations() -> None:
    """Assert .env.example contains Doppler note, 'NEVER commit .env', and markers."""
    content = ENV_EXAMPLE_PATH.read_text(encoding="utf-8")

    assert "doppler" in content.lower(), "Missing Doppler note in .env.example header"
    assert "never commit .env" in content.lower(), (
        "Missing 'NEVER commit .env' warning in .env.example"
    )

    # Verify every defined FLX_ variable has a [REQUIRED] or [OPTIONAL marker in nearby lines
    lines = content.splitlines()
    for i, line in enumerate(lines):
        line_clean = line.strip()
        if line_clean.startswith("FLX_") and "=" in line_clean:
            var_name = line_clean.split("=")[0].strip()
            # Look backwards up to 5 lines for [REQUIRED] or [OPTIONAL
            context_window = "\n".join(lines[max(0, i - 5) : i])
            assert "[REQUIRED]" in context_window or "[OPTIONAL" in context_window, (
                f"Missing [REQUIRED] or [OPTIONAL default=...] marker above {var_name}"
            )


def test_ansible_env_template_contains_all_settings_fields() -> None:
    """Assert all Settings model fields are covered in Ansible playbook if playbook exists."""
    if not ANSIBLE_PLAYBOOK_PATH.is_file():
        pytest.skip("Ansible playbook not present in this checkout")

    playbook_text = ANSIBLE_PLAYBOOK_PATH.read_text(encoding="utf-8")
    if "env.template" not in playbook_text:
        pytest.skip("Ansible playbook does not manage env.template")

    all_fields = Settings.model_fields.keys()
    missing: list[str] = []
    for field_name in all_fields:
        expected_var = f"FLX_{field_name.upper()}"
        if expected_var not in playbook_text:
            missing.append(f"{field_name} ({expected_var})")

    assert not missing, (
        f"Ansible env.template is missing {len(missing)} fields from Settings:\n"
        + "\n".join(f"  - {m}" for m in missing)
    )
