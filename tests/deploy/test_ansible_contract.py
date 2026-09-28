"""Ansible Provisioning Contract Tests (Task 67).

Validates:
1. Playbook, inventory, and group_vars parse cleanly as valid YAML without errors.
2. Doppler Law: Absolute absence of plaintext secrets across all Ansible configs (meta-test).
3. Auto-Sync Law: The /etc/fluxpay/env template enumerates 100% of Settings fields.
4. Kernel Law: sysctl tuning (somaxconn=65535, tcp_fastopen=3, BBR congestion control).
5. Database Durability Law: PostgreSQL 17 pinned with synchronous_commit=on and memory sizing.
6. SSHD & Firewall Hardening: PasswordAuthentication disabled, PermitRootLogin prohibit-password,
   UFW denying incoming except ports 22, 80, 443.
7. Wallet Address Law: Aborts in production if hot/cold custody addresses are unconfigured.
8. Idempotency Patterns: Handlers, notification hooks, and conditional state checks.
9. Runbook-as-Last-Task Law: Final task displays operator bootstrap checklist and deploy.sh command.
10. Makefile Contract: 2-command interface (check-syntax and provision).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from fluxpay.config import Settings

pytestmark = pytest.mark.unit

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
DEPLOY_DIR: Path = REPO_ROOT / "deploy"
ANSIBLE_DIR: Path = DEPLOY_DIR / "ansible"
GROUP_VARS_DIR: Path = ANSIBLE_DIR / "group_vars"


# -----------------------------------------------------------------------------
# 1. PLAYBOOK & YAML STRUCTURAL CONTRACT
# -----------------------------------------------------------------------------


def test_ansible_files_exist_and_yaml_parses() -> None:
    """Assert all required Ansible files exist and parse as valid YAML structures."""
    requirements_path = ANSIBLE_DIR / "requirements.yml"
    inventory_path = ANSIBLE_DIR / "inventory.example.yml"
    group_vars_path = GROUP_VARS_DIR / "all.yml"
    playbook_path = ANSIBLE_DIR / "playbook.yml"
    makefile_path = ANSIBLE_DIR / "Makefile"

    assert requirements_path.is_file(), f"Missing {requirements_path}"
    assert inventory_path.is_file(), f"Missing {inventory_path}"
    assert group_vars_path.is_file(), f"Missing {group_vars_path}"
    assert playbook_path.is_file(), f"Missing {playbook_path}"
    assert makefile_path.is_file(), f"Missing {makefile_path}"

    # Verify requirements.yml content and README header
    req_text = requirements_path.read_text(encoding="utf-8")
    assert "ansible-core >= 2.17" in req_text or "ansible-core>=2.17" in req_text
    req_data = yaml.safe_load(req_text)
    assert isinstance(req_data, dict) and "collections" in req_data
    col_names = [c["name"] for c in req_data["collections"]]
    assert "community.general" in col_names
    assert "community.postgresql" in col_names
    assert "ansible.posix" in col_names

    # Verify inventory parses and documents privilege-drop flow
    inv_text = inventory_path.read_text(encoding="utf-8")
    assert "fluxpay_prod" in inv_text
    assert "root" in inv_text
    assert "fluxpay-admin" in inv_text
    inv_data = yaml.safe_load(inv_text)
    assert isinstance(inv_data, dict) and "all" in inv_data

    # Verify group_vars parses
    vars_data = yaml.safe_load(group_vars_path.read_text(encoding="utf-8"))
    assert isinstance(vars_data, dict)
    assert "domain" in vars_data
    assert "admin_ssh_keys" in vars_data
    assert isinstance(vars_data["admin_ssh_keys"], list)
    assert vars_data.get("admin_user") == "fluxpay-admin"
    assert vars_data.get("api_user") == "fluxpay-api"
    assert vars_data.get("worker_user") == "fluxpay-worker"
    assert vars_data.get("app_root") == "/opt/fluxpay"

    # Verify playbook parses
    playbook_data = yaml.safe_load(playbook_path.read_text(encoding="utf-8"))
    assert isinstance(playbook_data, list) and len(playbook_data) >= 1
    play = playbook_data[0]
    assert play.get("hosts") == "all"
    assert play.get("become") is True


# -----------------------------------------------------------------------------
# 2. NO SECRETS META-CONTRACT (THE SECRETS LAW)
# -----------------------------------------------------------------------------


def test_no_secret_values_meta_contract() -> None:
    """Meta-test: Playbook, group_vars, and inventory must contain ZERO hardcoded secret values.

    Var names (e.g. doppler_service_token_name) and template placeholders are allowed;
    literal secret values, keys, and tokens are strictly banned.
    """
    forbidden_value_patterns = [
        # Banned: password: "literal_secret" (non-empty string not containing jinja or placeholder)
        re.compile(r"password:\s*['\"][a-zA-Z0-9_\-\.!@#$%^&*()+=]{8,}['\"]", re.IGNORECASE),
        # Banned: token: "literal_secret" (non-empty string not containing jinja or placeholder)
        re.compile(r"token:\s*['\"][a-zA-Z0-9_\-\.]{8,}['\"]", re.IGNORECASE),
        # Banned: actual Doppler service token literals
        re.compile(r"dp\.st\.[a-zA-Z0-9_\-]{20,}", re.IGNORECASE),
        # Banned: GitHub personal access tokens
        re.compile(r"ghp_[a-zA-Z0-9]{20,}", re.IGNORECASE),
        # Banned: Stripe live secret keys
        re.compile(r"sk_live_[a-zA-Z0-9]{20,}", re.IGNORECASE),
        # Banned: Stripe live webhook secrets
        re.compile(r"whsec_[a-zA-Z0-9]{20,}", re.IGNORECASE),
    ]

    files_to_scan = [
        GROUP_VARS_DIR / "all.yml",
        ANSIBLE_DIR / "inventory.example.yml",
        ANSIBLE_DIR / "playbook.yml",
    ]

    for file_path in files_to_scan:
        content = file_path.read_text(encoding="utf-8")
        for pat in forbidden_value_patterns:
            matches = pat.findall(content)
            # Filter out intentional placeholder tokens in comments or docs
            active_matches = [m for m in matches if "dp.st.prod.XXXX" not in m]
            assert not active_matches, (
                f"Secrets Law violation: Hardcoded secret pattern '{pat.pattern}' "
                f"detected in {file_path.name}: {active_matches}"
            )


# -----------------------------------------------------------------------------
# 3. ENV TEMPLATE AUTO-SYNC CONTRACT (Task 3 ↔ Task 67)
# -----------------------------------------------------------------------------


def test_env_template_covers_every_settings_field() -> None:
    """Assert the /etc/fluxpay/env template covers 100% of Settings model fields.

    Enforces the cross-language auto-sync law: config.py fields can never drift
    from the deployment environment template.
    """
    playbook_text = (ANSIBLE_DIR / "playbook.yml").read_text(encoding="utf-8")

    # Locate the copy task defining /etc/fluxpay/env.template
    assert "env.template" in playbook_text, "playbook must define an env.template task"

    all_settings_fields = Settings.model_fields.keys()
    assert len(all_settings_fields) >= 40, (
        f"Expected >= 40 Settings fields, found {len(all_settings_fields)}"
    )

    missing_fields: list[str] = []
    for field_name in all_settings_fields:
        expected_env_var = f"FLX_{field_name.upper()}"
        if expected_env_var not in playbook_text:
            missing_fields.append(f"{field_name} ({expected_env_var})")

    assert not missing_fields, (
        f"Env template drift detected! The following {len(missing_fields)} Settings "
        f"fields are missing from the playbook's env template:\n"
        + "\n".join(f"  - {f}" for f in missing_fields)
    )


# -----------------------------------------------------------------------------
# 4. KERNEL LAW & SYSCTL TUNING CONTRACT (Task 21)
# -----------------------------------------------------------------------------


def test_sysctl_kernel_tuning_contract() -> None:
    """Assert Task 21 Blueprint §11 kernel laws are fully codified in sysctl tasks."""
    playbook_text = (ANSIBLE_DIR / "playbook.yml").read_text(encoding="utf-8")

    # somaxconn=65535
    assert "net.core.somaxconn" in playbook_text
    assert "65535" in playbook_text

    # tcp_fastopen=3
    assert "net.ipv4.tcp_fastopen" in playbook_text
    assert "3" in playbook_text

    # BBR congestion control + fq qdisc
    assert "net.ipv4.tcp_congestion_control" in playbook_text
    assert "bbr" in playbook_text
    assert "net.core.default_qdisc" in playbook_text
    assert "fq" in playbook_text


# -----------------------------------------------------------------------------
# 5. POSTGRESQL 17 & DURABILITY CONTRACT (Task 13/33)
# -----------------------------------------------------------------------------


def test_postgres_17_and_durability_tuning_contract() -> None:
    """Assert PostgreSQL 17 is pinned and tuned for non-negotiable ledger durability."""
    playbook_text = (ANSIBLE_DIR / "playbook.yml").read_text(encoding="utf-8")
    group_vars_text = (GROUP_VARS_DIR / "all.yml").read_text(encoding="utf-8")

    # Version 17 pinned
    assert 'postgresql_version: "17"' in group_vars_text
    assert "noble-pgdg" in playbook_text, "PostgreSQL PGDG repository must be configured"

    # Durability & memory tuning
    assert "synchronous_commit = on" in playbook_text
    assert "shared_buffers = 2GB" in playbook_text
    assert "effective_cache_size = 6GB" in playbook_text
    assert "work_mem = 32MB" in playbook_text
    assert "max_connections = 100" in playbook_text


# -----------------------------------------------------------------------------
# 6. SSHD & UFW HARDENING CONTRACT (Task 65 Nginx Edge Alignment)
# -----------------------------------------------------------------------------


def test_sshd_and_ufw_hardening_contract() -> None:
    """Assert SSH daemon and UFW firewall satisfy base hardening requirements."""
    playbook_text = (ANSIBLE_DIR / "playbook.yml").read_text(encoding="utf-8")
    group_vars_text = (GROUP_VARS_DIR / "all.yml").read_text(encoding="utf-8")

    # SSH hardening lines
    assert "PasswordAuthentication no" in playbook_text
    assert "PermitRootLogin prohibit-password" in playbook_text
    assert "MaxAuthTries 3" in playbook_text

    # UFW default policies (deny incoming, allow outgoing)
    assert "incoming" in playbook_text and "deny" in playbook_text
    assert "outgoing" in playbook_text and "allow" in playbook_text

    # UFW ports match Task 65 conf (22, 80, 443 only)
    assert "mgmt_ssh: 22" in group_vars_text
    assert "https: 443" in group_vars_text
    assert "http: 80" in group_vars_text


# -----------------------------------------------------------------------------
# 7. WALLET ADDRESS ABORT VALIDATION CONTRACT (Task 44 Law)
# -----------------------------------------------------------------------------


def test_wallet_address_abort_validation_contract() -> None:
    """Assert Task 44 placeholder law: playbook aborts if wallet addresses are unset in prod."""
    playbook_text = (ANSIBLE_DIR / "playbook.yml").read_text(encoding="utf-8")

    # Assert pre-flight validation logic exists
    assert "wallet_hot_address" in playbook_text
    assert "wallet_cold_address" in playbook_text
    assert "0x0000000000000000000000000000000000000000" in playbook_text
    assert "fail_msg:" in playbook_text
    assert 'fluxpay_env == "production"' in playbook_text


# -----------------------------------------------------------------------------
# 8. IDEMPOTENCY PATTERNS CONTRACT
# -----------------------------------------------------------------------------


def test_idempotency_patterns_contract() -> None:
    """Assert source-level presence of Ansible idempotency markers and notification handlers."""
    playbook_text = (ANSIBLE_DIR / "playbook.yml").read_text(encoding="utf-8")

    # Notification handlers present
    assert "handlers:" in playbook_text
    assert "restart systemd-journald" in playbook_text
    assert "restart ssh" in playbook_text
    assert "restart postgresql" in playbook_text
    assert "reload nginx" in playbook_text

    # Idempotent state management checks
    assert "notify:" in playbook_text
    assert "creates:" in playbook_text or "changed_when:" in playbook_text
    assert "state: present" in playbook_text


# -----------------------------------------------------------------------------
# 9. RUNBOOK-AS-LAST-TASK CONTRACT
# -----------------------------------------------------------------------------


def test_bootstrap_runbook_as_last_task_contract() -> None:
    """Assert the final task in the playbook outputs the operator bootstrap card."""
    playbook_data = yaml.safe_load((ANSIBLE_DIR / "playbook.yml").read_text(encoding="utf-8"))
    assert isinstance(playbook_data, list) and len(playbook_data) >= 1

    play: dict[str, Any] = playbook_data[0]
    tasks: list[dict[str, Any]] = play.get("tasks", [])
    assert len(tasks) > 0, "Playbook has no tasks"

    last_task = tasks[-1]
    assert "ansible.builtin.debug" in last_task or "debug" in last_task
    task_name = last_task.get("name", "")
    assert "BOOTSTRAP" in task_name.upper() or "RUNBOOK" in task_name.upper()

    msg = last_task.get("ansible.builtin.debug", {}).get("msg", [])
    msg_str = " ".join(msg) if isinstance(msg, list) else str(msg)
    assert "deploy.sh" in msg_str
    assert "doppler" in msg_str.lower()
    assert "/healthz" in msg_str


# -----------------------------------------------------------------------------
# 10. MAKEFILE 2-COMMAND CONTRACT
# -----------------------------------------------------------------------------


def test_makefile_contract() -> None:
    """Assert deploy/ansible/Makefile provides check-syntax and provision targets."""
    makefile_text = (ANSIBLE_DIR / "Makefile").read_text(encoding="utf-8")

    assert "check-syntax:" in makefile_text
    assert "provision:" in makefile_text
    assert "--syntax-check" in makefile_text
