"""Permanent Meta-Guard: Zero-Smart-Contract Architecture Enforcement.

Guarantees that no Solidity contracts are authored, deployed, or owned by FluxPay.
The server observes the chain; custody execution is strictly off-server via Gnosis Safe.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_DIR = REPO_ROOT / "contracts"

VIOLATION_MSG = (
    "SECURITY VIOLATION: FluxPay authors no smart contracts; "
    "custody execution is off-server via Gnosis Safe (docs/ledger.md)."
)

ALLOWED_CONTRACT_FILES = {"openapi.json", "webhook.schema.json"}


def test_contracts_directory_contains_only_approved_schemas() -> None:
    """Assert contracts/ directory contains ONLY openapi.json and webhook.schema.json."""
    assert CONTRACTS_DIR.is_dir(), f"Missing contracts directory: {CONTRACTS_DIR}"

    actual_files = {p.name for p in CONTRACTS_DIR.iterdir() if p.is_file()}
    assert actual_files == ALLOWED_CONTRACT_FILES, (
        f"{VIOLATION_MSG} Unexpected files in contracts/: {actual_files - ALLOWED_CONTRACT_FILES}"
    )


def test_no_solidity_files_anywhere_in_repo() -> None:
    """Assert no *.sol files exist anywhere in the repository tree."""
    ignored_dirs = {".git", ".venv", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules"}

    sol_files: list[Path] = []
    for p in REPO_ROOT.rglob("*.sol"):
        if any(ignored in p.parts for ignored in ignored_dirs):
            continue
        if p.is_file():
            sol_files.append(p)

    assert not sol_files, f"{VIOLATION_MSG} Found Solidity files: {sol_files}"
