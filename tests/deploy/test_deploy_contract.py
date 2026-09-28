"""Deploy Foundation Contract Tests (Task 65).

Validates:
1. Systemd unit hardening inventories, drain triangle timing, and unprivileged user configuration.
2. Nginx edge structural contract (blue-green upstreams, active include, TLS 1.3, security headers).
3. migrate.sh SQL runner syntax (bash -n) and schema_migrations bookkeeping contract.
4. deploy.sh syntax (bash -n), refusal mode, rollback mode, and healthz polling.
5. main.py GET /healthz liveness probe route inspection and response payload.
6. Doppler Law: Absolute absence of plaintext secrets across deploy configs.
"""

from __future__ import annotations

import configparser
import importlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from starlette.routing import Route

from fluxpay import __version__

pytestmark = pytest.mark.unit

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
DEPLOY_DIR: Path = REPO_ROOT / "deploy"
SYSTEMD_DIR: Path = DEPLOY_DIR / "systemd"
NGINX_DIR: Path = DEPLOY_DIR / "nginx"

REQUIRED_HARDENING_KEYS: list[str] = [
    "nonewprivileges",
    "protectsystem",
    "readwritepaths",
    "protecthome",
    "privatetmp",
    "privatedevices",
    "protectkerneltunables",
    "protectkernelmodules",
    "protectcontrolgroups",
    "protectclock",
    "protecthostname",
    "restrictaddressfamilies",
    "memorymax",
    "tasksmax",
    "limitnofile",
    "systemcallfilter",
    "systemcallerrornumber",
    "lockpersonality",
    "restrictnamespaces",
    "restrictrealtime",
    "protectproc",
    "procsubset",
    "capabilityboundingset",
]


def _find_working_bash() -> str | None:
    """Find a functional bash executable across Linux CI and Windows host environments."""
    candidates = [
        "C:\\Program Files\\Git\\bin\\bash.exe",
        "C:\\Program Files\\Git\\usr\\bin\\bash.exe",
        "/bin/bash",
        "/usr/bin/bash",
        "/usr/local/bin/bash",
    ]
    for c in candidates:
        if Path(c).is_file():
            return c
    w = shutil.which("bash")
    if w and not w.lower().endswith(r"system32\bash.exe"):
        return w
    return None


# -----------------------------------------------------------------------------
# 1. SYSTEMD API UNIT CONTRACT
# -----------------------------------------------------------------------------


def test_systemd_api_unit_hardening_and_contract() -> None:
    """Assert fluxpay-api@.service satisfies the complete hardening inventory and drain triangle."""
    unit_path = SYSTEMD_DIR / "fluxpay-api@.service"
    assert unit_path.is_file(), f"API unit file missing: {unit_path}"

    cp = configparser.ConfigParser(allow_no_value=True, strict=False, interpolation=None)
    cp.read(unit_path, encoding="utf-8")

    assert cp.has_section("Unit"), "Missing [Unit] section"
    assert cp.has_section("Service"), "Missing [Service] section"
    assert cp.has_section("Install"), "Missing [Install] section"

    service = cp["Service"]

    # Security: unprivileged service user
    assert service.get("User") == "fluxpay-api", "User must be fluxpay-api (not root)"
    assert service.get("Group") == "fluxpay", "Group must be fluxpay"
    assert service.get("Type") == "exec", "Type must be exec"

    # Environment & Secrets: Doppler law
    assert service.get("EnvironmentFile") == "/etc/fluxpay/env"

    # ExecStart: UDS socket bound
    exec_start = service.get("ExecStart", "")
    assert "unix:/run/fluxpay/api-%i.sock" in exec_start, "ExecStart must bind to UDS socket"
    assert "gunicorn fluxpay.main:app" in exec_start

    # Drain Triangle: TimeoutStopSec >= graceful-timeout (35s >= 30s)
    timeout_stop_sec = int(service.get("TimeoutStopSec", "0"))
    assert timeout_stop_sec >= 35, f"TimeoutStopSec={timeout_stop_sec} must be >= 35s"

    match_graceful = re.search(r"--graceful-timeout\s+(\d+)", exec_start)
    assert match_graceful is not None, "Missing --graceful-timeout in ExecStart"
    graceful_timeout = int(match_graceful.group(1))
    assert timeout_stop_sec >= graceful_timeout, (
        f"TimeoutStopSec ({timeout_stop_sec}) must be >= graceful-timeout ({graceful_timeout})"
    )

    match_timeout = re.search(r"--timeout\s+(\d+)", exec_start)
    assert match_timeout is not None, "Missing --timeout in ExecStart"
    hard_timeout = int(match_timeout.group(1))
    assert hard_timeout == 60, "Gunicorn hard timeout must be 60s"

    # Hardening Inventory: All 20+ keys present
    service_keys_lower = {k.lower(): v for k, v in service.items()}
    for key in REQUIRED_HARDENING_KEYS:
        assert key in service_keys_lower, f"Missing hardening key in API unit: {key}"

    assert service_keys_lower["nonewprivileges"] == "true"
    assert service_keys_lower["protectsystem"] == "strict"
    assert "AF_UNIX" in service_keys_lower["restrictaddressfamilies"]
    assert "AF_INET" in service_keys_lower["restrictaddressfamilies"]


# -----------------------------------------------------------------------------
# 2. SYSTEMD WORKER UNIT CONTRACT
# -----------------------------------------------------------------------------


def test_systemd_worker_unit_hardening_and_contract() -> None:
    """Assert fluxpay-worker@.service satisfies hardening, unprivileged user, and drain laws."""
    unit_path = SYSTEMD_DIR / "fluxpay-worker@.service"
    assert unit_path.is_file(), f"Worker unit file missing: {unit_path}"

    cp = configparser.ConfigParser(allow_no_value=True, strict=False, interpolation=None)
    cp.read(unit_path, encoding="utf-8")

    assert cp.has_section("Unit")
    assert cp.has_section("Service")
    assert cp.has_section("Install")

    service = cp["Service"]

    assert service.get("User") == "fluxpay-worker", "User must be fluxpay-worker (not root)"
    assert service.get("Group") == "fluxpay"
    assert service.get("Type") == "exec"

    # Drain law for workers: TimeoutStopSec=40
    timeout_stop_sec = int(service.get("TimeoutStopSec", "0"))
    assert timeout_stop_sec >= 40, f"TimeoutStopSec={timeout_stop_sec} must be >= 40s"

    # ExecStart: Subcommand-based invocation via webhook_entrypoints
    exec_start = service.get("ExecStart", "")
    assert "python -m fluxpay.workers.webhook_entrypoints %i" in exec_start

    # Hardening Inventory: All 20+ keys present (deliberately duplicated for auditability)
    service_keys_lower = {k.lower(): v for k, v in service.items()}
    for key in REQUIRED_HARDENING_KEYS:
        assert key in service_keys_lower, f"Missing hardening key in Worker unit: {key}"


# -----------------------------------------------------------------------------
# 3. WORKER ENTRYPOINTS IN-PROCESS CONTRACT
# -----------------------------------------------------------------------------


def test_worker_entrypoints_importable_and_contract() -> None:
    """Verify webhook_entrypoints module is cleanly importable and exposes daemon entrypoints."""
    module = importlib.import_module("fluxpay.workers.webhook_entrypoints")
    assert hasattr(module, "main_fanout"), "Missing main_fanout entrypoint"
    assert hasattr(module, "main_delivery"), "Missing main_delivery entrypoint"
    assert hasattr(module, "main"), "Missing main subcommand dispatcher"
    assert callable(module.main_fanout)
    assert callable(module.main_delivery)
    assert callable(module.main)

    # Subcommand validation: invalid arg exits with code 1
    with pytest.raises(SystemExit) as exc_info:
        module.main(["invalid_command"])
    assert exc_info.value.code == 1


# -----------------------------------------------------------------------------
# 4. NGINX EDGE STRUCTURAL CONTRACT
# -----------------------------------------------------------------------------


def test_nginx_conf_structural_contract() -> None:
    """Assert deploy/nginx/fluxpay.conf contains valid upstreams, TLS, security headers, and UDS."""
    conf_path = NGINX_DIR / "fluxpay.conf"
    assert conf_path.is_file(), f"Nginx config missing: {conf_path}"

    content = conf_path.read_text(encoding="utf-8")

    # Upstream blocks defined
    assert "upstream api_blue" in content
    assert "upstream api_green" in content
    assert "server unix:/run/fluxpay/api-1.sock;" in content
    assert "server unix:/run/fluxpay/api-2.sock;" in content

    # Active include pattern for zero-downtime blue-green switch
    assert "include /etc/nginx/fluxpay-active.conf;" in content

    # TLS 1.3 institutional standard
    assert "ssl_protocols TLSv1.3;" in content
    assert "ssl_certificate /etc/ssl/fluxpay/fullchain.pem;" in content

    # Mandatory security headers
    assert 'Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' in content
    assert "X-Content-Type-Options nosniff always;" in content
    assert "X-Frame-Options DENY always;" in content
    assert "Referrer-Policy strict-origin-when-cross-origin always;" in content

    # Ingress body limit: 1m (app enforces 64KiB)
    assert "client_max_body_size 1m;" in content

    # Idempotency safety: never retry upstream POSTs
    assert "proxy_next_upstream off;" in content

    # Drain triangle closed: Nginx 65s > Gunicorn 60s
    assert "proxy_read_timeout 65s;" in content

    # Static assets direct serving
    assert "location /static/ {" in content
    assert "alias /opt/fluxpay/current/static/;" in content

    # Process health check probe
    assert "location = /healthz {" in content
    assert "access_log off;" in content

    # Block balance check (braces balanced)
    open_braces = content.count("{")
    close_braces = content.count("}")
    assert open_braces == close_braces, (
        f"Unbalanced braces in Nginx conf: {open_braces} != {close_braces}"
    )


# -----------------------------------------------------------------------------
# 5. MIGRATE.SH CONTRACT & SYNTAX
# -----------------------------------------------------------------------------


def test_migrate_sh_syntax_and_contract() -> None:
    """Assert deploy/migrate.sh is bash -n clean and enforces schema_migrations bookkeeping."""
    script_path = DEPLOY_DIR / "migrate.sh"
    assert script_path.is_file(), f"migrate.sh missing: {script_path}"

    bash_bin = _find_working_bash()
    if bash_bin is not None:
        res = subprocess.run(  # noqa: S603
            [bash_bin, "-n", str(script_path)], capture_output=True, text=True
        )
        assert res.returncode == 0, f"migrate.sh bash -n failed:\n{res.stderr}"

    content = script_path.read_text(encoding="utf-8")
    assert "set -euo pipefail" in content
    assert "schema_migrations" in content, "Bookkeeping table schema_migrations must be created"
    assert "ON_ERROR_STOP=1" in content, "psql must execute with ON_ERROR_STOP=1 for fail-fast"
    assert "FLX_PG_DSN" in content
    assert "sorted_files" in content or "sort" in content, "Migrations must execute in sorted order"

    # FIX-6 Guard: Parameterized filename in psql (no raw string concat)
    assert ":'fname'" in content or (":'" in content and "fname'" in content), (
        "migrate.sh must bind filename via psql variable :'fname'"
    )
    assert "WHERE filename = '$" not in content, (
        "migrate.sh must not concatenate '$filename' into SQL query"
    )


# -----------------------------------------------------------------------------
# 6. DEPLOY.SH CONTRACT & SYNTAX
# -----------------------------------------------------------------------------


def test_deploy_sh_syntax_and_contract() -> None:
    """Assert deploy/deploy.sh is bash -n clean and implements refusal, rollback, and polling."""
    script_path = DEPLOY_DIR / "deploy.sh"
    assert script_path.is_file(), f"deploy.sh missing: {script_path}"

    bash_bin = _find_working_bash()
    if bash_bin is not None:
        res = subprocess.run(  # noqa: S603
            [bash_bin, "-n", str(script_path)], capture_output=True, text=True
        )
        assert res.returncode == 0, f"deploy.sh bash -n failed:\n{res.stderr}"

    content = script_path.read_text(encoding="utf-8")
    assert "set -euo pipefail" in content

    # CI refusal mode: refuses without assertion
    assert "--i-know-main-is-green" in content
    assert "DEPLOY REFUSED" in content

    # Emergency rollback mode: < 5 second switch
    assert "--rollback" in content
    assert ".previous-release" in content

    # Doppler env guard & Nginx conf early guard (FIX-5)
    assert "/etc/fluxpay/env" in content
    assert "/etc/nginx/fluxpay.conf" in content

    # Instance-aware rolling restart and socket health poll
    assert "poll_healthz" in content
    assert "/run/fluxpay/api-1.sock" in content
    assert "/run/fluxpay/api-2.sock" in content

    # Symlink switch
    assert "ln -sfn" in content
    assert "/opt/fluxpay/current" in content

    # Idempotent worker restart
    assert "systemctl restart fluxpay-worker@" in content

    # FIX-7 Guard: DSN extraction uses sed and does not use tr -d '"'
    assert "sed -E" in content, "deploy.sh must use sed -E for DSN extraction"
    dsn_lines = [line for line in content.splitlines() if "FLX_PG_DSN" in line]
    for line in dsn_lines:
        assert 'tr -d \'"\'' not in line and "tr -d '\"'" not in line, (
            "deploy.sh must not use tr -d '\"' in DSN extraction"
        )


def test_deploy_sh_inactive_first_zero_downtime_restart() -> None:
    """Assert deploy.sh implements inactive-first restart ordering for true zero-downtime."""
    script_path = DEPLOY_DIR / "deploy.sh"
    content = script_path.read_text(encoding="utf-8")

    # Inactive-first logic presence
    assert "ACTIVE=" in content, "deploy.sh must detect and set ACTIVE="
    assert "TRUE ZERO-DOWNTIME" in content

    # Find step 9-10 boundaries
    step9_idx = content.find("9. TRUE ZERO-DOWNTIME")
    assert step9_idx != -1, "Missing step 9 marker in deploy.sh"
    step_content = content[step9_idx:]

    inactive_restart_idx = step_content.find('systemctl restart "$INACTIVE_UNIT"')
    active_rewrite_idx = step_content.find('echo "proxy_pass http://api_${INACTIVE};"')
    nginx_reload_idx = step_content.find("nginx -s reload")
    active_restart_idx = step_content.find('systemctl restart "$ACTIVE_UNIT"')

    assert inactive_restart_idx != -1, "Missing inactive instance restart"
    assert active_rewrite_idx != -1, "Missing active include rewrite"
    assert nginx_reload_idx != -1, "Missing nginx reload"
    assert active_restart_idx != -1, "Missing active instance restart"

    # Ordering: restart of non-active instance BEFORE active include rewrite
    assert inactive_restart_idx < active_rewrite_idx, (
        "Inactive instance must be restarted BEFORE active include rewrite"
    )

    # Ordering: nginx reload line must appear BETWEEN the two systemctl restart blocks
    assert inactive_restart_idx < nginx_reload_idx < active_restart_idx, (
        "Nginx reload must appear BETWEEN the inactive and active systemctl restart blocks"
    )


# -----------------------------------------------------------------------------
# 7. MAIN.PY HEALTHZ ROUTE CONTRACT
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_main_healthz_route_contract() -> None:
    """Assert GET /healthz route is registered on the application and returns process liveness."""
    # Provide synthetic Doppler configuration for app creation without DB connection
    os.environ["FLX_PG_DSN"] = "postgresql://test:test@localhost:5432/test"
    os.environ["FLX_VAULT_MASTER_KEY"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    os.environ["FLX_WEBHOOK_SIGNING_KEY"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    from fluxpay.main import create_app

    app = create_app()

    # Introspect registered routes
    routes = [r for r in app.routes if isinstance(r, Route)]
    healthz_route = next((r for r in routes if r.path == "/healthz"), None)
    assert healthz_route is not None, "GET /healthz route must be registered on application"
    assert healthz_route.methods is not None and "GET" in healthz_route.methods

    # Execute healthz endpoint coroutine
    endpoint: Any = healthz_route.endpoint
    result = await endpoint()
    assert result == {"status": "ok", "version": __version__}


# -----------------------------------------------------------------------------
# 8. NO SECRETS META-TEST (DOPPLER LAW)
# -----------------------------------------------------------------------------


def test_no_secrets_meta_contract() -> None:
    """Meta-test: Systemd units and Nginx configs must contain ZERO hardcoded secrets."""
    forbidden_patterns = [
        re.compile(r"password\s*=\s*['\"]?[a-zA-Z0-9_\-]{4,}", re.IGNORECASE),
        re.compile(r"secret\s*=\s*['\"]?[a-zA-Z0-9_\-]{8,}", re.IGNORECASE),
        re.compile(r"bearer\s+[a-zA-Z0-9_\-\.]{10,}", re.IGNORECASE),
        re.compile(r"ghp_[a-zA-Z0-9]{20,}", re.IGNORECASE),
    ]

    files_to_check: list[Path] = []
    files_to_check.extend(SYSTEMD_DIR.glob("*.service"))
    files_to_check.extend(SYSTEMD_DIR.glob("*.timer"))
    files_to_check.extend(NGINX_DIR.glob("*.conf"))

    assert len(files_to_check) >= 6, "Expected at least 6 config files to scan"

    for file_path in files_to_check:
        text = file_path.read_text(encoding="utf-8")
        for pat in forbidden_patterns:
            matches = pat.findall(text)
            assert not matches, (
                f"Doppler Law violation: Secret-like pattern '{pat.pattern}' "
                f"found in {file_path.name}: {matches}"
            )
