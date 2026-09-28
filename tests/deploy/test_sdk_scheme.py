"""Permanent Meta-Guard: SDK Signing Scheme & Cross-Language KAT Contract.

Asserts that Node SDK signing.ts strictly implements FLXP1 HMAC-SHA256, contains
no unauthorized asymmetric crypto (Ed25519/NaCl), and matches Python's canonical
implementation byte-for-byte on all frozen KAT vectors.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from fluxpay.gateway.canonical import get_frozen_vectors, sign

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
NODE_SIGNING_TS = REPO_ROOT / "sdk" / "node" / "fluxpay" / "signing.ts"
NODE_KAT_RUNNER = REPO_ROOT / "sdk" / "node" / "tests" / "run_kat.mjs"


def test_node_signing_ts_structure_and_scheme() -> None:
    """Assert Node signing.ts implements FLXP1 HMAC-SHA256 and has no Ed25519/NaCl."""
    assert NODE_SIGNING_TS.is_file(), f"Missing Node signing file: {NODE_SIGNING_TS}"

    content = NODE_SIGNING_TS.read_text(encoding="utf-8")

    # Assert required constructions
    assert "FLXP1" in content, "Node signing.ts must declare FLXP1 scheme"
    assert "sha256" in content.lower(), "Node signing.ts must use SHA256"
    assert "hmac" in content.lower(), "Node signing.ts must use HMAC construction"

    # Assert banned schemes (zero asymmetric creep)
    banned_tokens = ["ed25519", "Ed25519", "nacl", "tweetnacl"]
    for banned in banned_tokens:
        assert banned not in content, (
            f"SECURITY VIOLATION: Unauthorized crypto primitive '{banned}' "
            f"found in {NODE_SIGNING_TS}"
        )


def test_python_kat_frozen_vectors() -> None:
    """Assert Python gateway canonical.py matches all 3 frozen KAT vectors."""
    vectors = get_frozen_vectors()
    assert len(vectors) == 3, f"Expected exactly 3 frozen KAT vectors, found {len(vectors)}"

    for i, v in enumerate(vectors):
        computed_sig = sign(
            secret=v["secret"],
            method=v["method"],
            path=v["path"],
            timestamp=v["timestamp"],
            nonce=v["nonce"],
            body=v["body"],
        )
        expected = v["expected_signature"]
        assert computed_sig == expected, (
            f"Python signature mismatch on vector {i + 1}: {computed_sig} != {expected}"
        )


def test_node_cross_language_kat_runner() -> None:
    """Run Node.js cross-language KAT test runner if node is available."""
    node_bin = shutil.which("node")
    if node_bin is None:
        pytest.skip("Node.js binary not available in environment; tested via static KAT vectors")

    assert NODE_KAT_RUNNER.is_file(), f"Missing Node KAT runner at {NODE_KAT_RUNNER}"

    res = subprocess.run(  # noqa: S603
        [node_bin, str(NODE_KAT_RUNNER)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, (
        f"Node KAT runner failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
    )
    assert "All 3 KAT vectors PASSED" in res.stdout
