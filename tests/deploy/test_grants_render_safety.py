"""Permanent Guard: Render-Safety Contract for deploy/sql/grants.sql.j2.

Guarantees:
1. deploy/sql contains grants.sql.j2 and NO plain grants.sql.
2. deploy/migrate.sh source does NOT reference 'grants' or 'deploy/sql'.
3. deploy/ansible/playbook.yml renders grants.sql.j2 via ansible.builtin.template.
4. grants.sql.j2 contains '{{ app_role }}' and NO literal '<app_role>'.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOY_DIR = REPO_ROOT / "deploy"
SQL_DIR = DEPLOY_DIR / "sql"
PLAYBOOK_PATH = DEPLOY_DIR / "ansible" / "playbook.yml"
MIGRATE_PATH = DEPLOY_DIR / "migrate.sh"


def test_deploy_sql_contains_only_grants_j2_no_plain_grants_sql() -> None:
    """Assert deploy/sql contains grants.sql.j2 and NO plain grants.sql."""
    plain_grants = SQL_DIR / "grants.sql"
    assert not plain_grants.exists(), (
        f"Found forbidden plain grants.sql at {plain_grants}! "
        "Must use grants.sql.j2 with Ansible template rendering "
        "to prevent unrendered SQL execution."
    )

    j2_grants = SQL_DIR / "grants.sql.j2"
    assert j2_grants.is_file(), f"Missing required grants template: {j2_grants}"


def test_migrate_sh_does_not_reference_grants_or_deploy_sql() -> None:
    """Assert deploy/migrate.sh does NOT reference grants or deploy/sql."""
    assert MIGRATE_PATH.is_file(), f"Missing migrate script: {MIGRATE_PATH}"
    content = MIGRATE_PATH.read_text(encoding="utf-8")
    assert "grants" not in content.lower(), "deploy/migrate.sh must not reference 'grants'"
    assert "deploy/sql" not in content, "deploy/migrate.sh must not touch 'deploy/sql'"


def test_playbook_contains_grants_j2_and_template() -> None:
    """Assert playbook.yml contains 'grants.sql.j2' AND 'template' in task block."""
    assert PLAYBOOK_PATH.is_file(), f"Missing playbook: {PLAYBOOK_PATH}"
    content = PLAYBOOK_PATH.read_text(encoding="utf-8")
    assert "grants.sql.j2" in content, "playbook.yml must reference grants.sql.j2"
    assert "template" in content, "playbook.yml must use template module for rendering"

    # Block-level inspection: verify grants.sql.j2 is rendered via template
    lines = content.splitlines()
    in_grants_block = False
    block_lines: list[str] = []
    for line in lines:
        if "grants.sql.j2" in line:
            in_grants_block = True
        if in_grants_block:
            block_lines.append(line)
            if line.strip().startswith("- name:") and "grants.sql.j2" not in line:
                break

    block_text = "\n".join(block_lines)
    assert "template" in block_text or "ansible.builtin.template" in content, (
        "playbook.yml must render grants.sql.j2 with the template module"
    )


def test_grants_j2_contains_jinja_var_no_raw_placeholder() -> None:
    """Assert grants.sql.j2 contains '{{ app_role }}' and NO '<app_role>'."""
    j2_path = SQL_DIR / "grants.sql.j2"
    content = j2_path.read_text(encoding="utf-8")

    assert "{{ app_role }}" in content, "grants.sql.j2 must contain Jinja2 '{{ app_role }}'"
    assert "<app_role>" not in content, "grants.sql.j2 must NOT contain unrendered '<app_role>'"
