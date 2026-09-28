"""Environment contract integration test between scripts/gen_env.sh and fluxpay.config.Settings.

This test exists to enforce that the local environment generator produces values that strictly
conform to the twelve-factor configuration contract and pass all Task 3 runtime validators.
If an engineer modifies Settings validators (e.g. key length, entropy constraints, DSN formats)
or updates .env.example without updating the generator, CI fails HERE — not on a new hire's laptop.
"""

import base64
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from fluxpay.config import Settings


def test_gen_env_produces_valid_settings_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validate that scripts/gen_env.sh outputs an environment file satisfying Settings invariants.

    Asserts that:
    1. scripts/gen_env.sh executes successfully and generates the target .env file.
    2. Settings(_env_file=...) constructs without raising any ValidationError.
    3. Generated secrets are cryptographically random and do not contain .env.example placeholders.
    4. Generated vault master key decodes to exactly 32 bytes (AES-256 requirement).
    5. Generated webhook signing key is at least 32 characters long.
    """
    # 1. Clean ambient environment to prevent ambient variables from leaking into Settings
    for key in list(os.environ.keys()):
        if key.startswith("FLX_"):
            monkeypatch.delenv(key, raising=False)

    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "gen_env.sh"
    assert script_path.is_file(), f"gen_env.sh script not found at {script_path}"

    out_env_path = tmp_path / ".env"

    # 2. Determine appropriate bash interpreter across platforms
    bash_bin = shutil.which("bash")
    if os.name == "nt":
        git_bash = Path("C:/Program Files/Git/bin/bash.exe")
        if git_bash.is_file():
            bash_bin = str(git_bash)

    assert bash_bin is not None, "A valid bash executable must be present on PATH"

    # 3. Execute scripts/gen_env.sh targeting the temporary path
    result = subprocess.run(  # noqa: S603
        [bash_bin, str(script_path), "--out", str(out_env_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert out_env_path.is_file(), f"Expected .env file to be created at {out_env_path}"
    assert "Generated" in result.stdout

    # 4. Load Settings directly using pydantic-settings _env_file override
    settings = Settings(_env_file=str(out_env_path))

    # 5. Assert default development service endpoints
    assert settings.pg_dsn == "postgresql://fluxpay:fluxpay@localhost:5432/fluxpay"
    assert settings.valkey_url == "redis://localhost:6379/0"
    assert settings.env == "development"

    # 6. Verify cryptographic secret invariants
    # Vault master key: base64 decodes to exactly 32 bytes
    decoded_vault = base64.b64decode(settings.vault_master_key, validate=True)
    assert len(decoded_vault) == 32

    # Webhook signing key: min length 32 chars
    assert len(settings.webhook_signing_key) >= 32

    # 7. Assert generated file does NOT contain raw .env.example placeholder strings
    env_content = out_env_path.read_text(encoding="utf-8")
    assert "CHANGE_ME_base64_of_openssl_rand_base64_32" not in env_content
    assert "CHANGE_ME_min_32_char_hex_string_from_openssl" not in env_content
    assert settings.vault_master_key != "CHANGE_ME_base64_of_openssl_rand_base64_32"
    assert settings.webhook_signing_key != "CHANGE_ME_min_32_char_hex_string_from_openssl"
