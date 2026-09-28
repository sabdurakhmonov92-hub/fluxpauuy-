"""Pure unit tests for dashboard ops form parsers, security headers,
and template invariants (Task 62).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fluxpay.dashboard.ops import (
    build_no_store_headers,
    parse_int_field,
    parse_limits_form,
)
from fluxpay.risk.limits import AgentLimits

TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "templates"


# -----------------------------------------------------------------------------
# 1. INTEGER COERCION & DEFENSIVE FORM GUARDS
# -----------------------------------------------------------------------------


def test_parse_int_field_valid_integers() -> None:
    """Validate parsing of valid string and integer representations."""
    assert parse_int_field("42", "count") == 42
    assert parse_int_field("  100  ", "count") == 100
    assert parse_int_field(500, "count") == 500
    assert parse_int_field("0", "zero", min_val=0) == 0


def test_parse_int_field_rejects_malformed_inputs() -> None:
    """Validate defensive rejection of non-integers, floats, and empty values."""
    # Alphabetic string
    with pytest.raises(ValueError, match="Field 'rate' must be a valid integer"):
        parse_int_field("abc", "rate")

    # Float string (strict integer law)
    with pytest.raises(ValueError, match=r"must be an integer, got float string '1\.5'"):
        parse_int_field("1.5", "rate")

    # Empty string
    with pytest.raises(ValueError, match="Field 'rate' cannot be empty"):
        parse_int_field("   ", "rate")

    # None
    with pytest.raises(ValueError, match="Field 'rate' is required"):
        parse_int_field(None, "rate")


def test_parse_int_field_bounds_enforcement() -> None:
    """Validate min_val and max_val boundary checks."""
    assert parse_int_field("10", "val", min_val=10, max_val=20) == 10
    assert parse_int_field("20", "val", min_val=10, max_val=20) == 20

    with pytest.raises(ValueError, match="Field 'val' must be >= 10, got 9"):
        parse_int_field("9", "val", min_val=10, max_val=20)

    with pytest.raises(ValueError, match="Field 'val' must be <= 20, got 21"):
        parse_int_field("21", "val", min_val=10, max_val=20)


# -----------------------------------------------------------------------------
# 2. LIMITS POLICY FORM PARSER (TASK 28 MIRROR)
# -----------------------------------------------------------------------------


def test_parse_limits_form_valid() -> None:
    """Validate successful parsing of compliant limits form payload."""
    form_data = {
        "velocity_limit": "10",
        "velocity_window_s": "120",
        "max_single_tx_minor": "50000000",
        "daily_outflow_cap_minor": "200000000",
    }
    limits, error = parse_limits_form(form_data)
    assert error is None
    assert isinstance(limits, AgentLimits)
    assert limits.velocity_limit == 10
    assert limits.velocity_window_s == 120
    assert limits.max_single_tx_minor == 50_000_000
    assert limits.daily_outflow_cap_minor == 200_000_000


@pytest.mark.parametrize(
    ("bad_field", "bad_value", "expected_err"),
    [
        ("velocity_limit", "abc", "must be a valid integer"),
        ("velocity_limit", "0", "must be >= 1"),
        ("velocity_limit", "101", "must be <= 100"),
        ("velocity_window_s", "9", "must be >= 10"),
        ("velocity_window_s", "3601", "must be <= 3600"),
        ("max_single_tx_minor", "0", "must be >= 1"),
        ("max_single_tx_minor", "-5", "must be >= 1"),
        ("daily_outflow_cap_minor", "0", "must be >= 1"),
        ("daily_outflow_cap_minor", "not_a_number", "must be a valid integer"),
    ],
)
def test_parse_limits_form_validation_failures(
    bad_field: str, bad_value: str, expected_err: str
) -> None:
    """Validate range and type error messages for all invalid limits fields."""
    base_data = {
        "velocity_limit": "5",
        "velocity_window_s": "60",
        "max_single_tx_minor": "100000000",
        "daily_outflow_cap_minor": "500000000",
    }
    base_data[bad_field] = bad_value
    limits, error = parse_limits_form(base_data)
    assert limits is None
    assert error is not None
    assert expected_err in error


# -----------------------------------------------------------------------------
# 3. SECURITY HEADERS KNOWN ANSWER TEST (KAT)
# -----------------------------------------------------------------------------


def test_build_no_store_headers_kat() -> None:
    """Security Header Law KAT: One-time secret screens must disallow caching completely."""
    headers = build_no_store_headers()
    assert headers == {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }


# -----------------------------------------------------------------------------
# 4. TEMPLATE PERSISTENCE BAN META-TEST (DRIFT ALARM)
# -----------------------------------------------------------------------------


def test_template_persistence_ban_meta_test() -> None:
    """Security Invariant: Templates must NEVER store plaintext credentials in browser storage.

    Verifies across all .html files:
    - localStorage is strictly absent.
    - sessionStorage is strictly absent.
    - indexedDB is strictly absent.
    """
    assert TEMPLATES_DIR.is_dir(), f"Templates directory not found at {TEMPLATES_DIR}"
    html_files = list(TEMPLATES_DIR.glob("*.html"))
    assert len(html_files) >= 9, f"Expected at least 9 templates, found {len(html_files)}"

    for html_file in html_files:
        content = html_file.read_text(encoding="utf-8")
        assert "localStorage" not in content, (
            f"Violation in {html_file.name}: localStorage is forbidden by custody law."
        )
        assert "sessionStorage" not in content, (
            f"Violation in {html_file.name}: sessionStorage is forbidden by custody law."
        )
        assert "indexedDB" not in content, (
            f"Violation in {html_file.name}: indexedDB is forbidden by custody law."
        )


def test_treasury_template_read_only_law() -> None:
    """Read-Only Treasury Law: Web UI cannot perform treasury votes; CLI is authoritative.

    Asserts:
    - "hx-post" is present exactly ZERO times in treasury.html.
    - Prominent runbook guidance for CLI voting is displayed.
    """
    treasury_path = TEMPLATES_DIR / "treasury.html"
    assert treasury_path.is_file(), "treasury.html not found."
    content = treasury_path.read_text(encoding="utf-8")

    # Greppable zero-mutation assertion
    assert "hx-post" not in content, "Violation: treasury.html must contain 'hx-post' zero times."
    assert "vote via CLI: python -m fluxpay.treasury.cli vote" in content, (
        "treasury.html must contain the CLI voting runbook hint."
    )


# -----------------------------------------------------------------------------
# 5. ADMIN LIMITS ROUTER ROLE ENFORCEMENT & ROUTE FACTORY (TASK 29/62 PARITY)
# -----------------------------------------------------------------------------


def test_admin_limits_router_role_enforcement() -> None:
    """Validate _require_role in limits_router enforces role separation."""
    from unittest.mock import MagicMock

    from fluxpay.admin.keycloak import AdminPrincipal
    from fluxpay.admin.limits_router import _require_role, create_limits_routes
    from fluxpay.shared.errors import ForbiddenError

    admin_p = AdminPrincipal(sub="sub_1", role="admin", email="admin@fluxpay.local")
    support_p = AdminPrincipal(sub="sub_2", role="support", email="sup@fluxpay.local")

    assert _require_role(admin_p, {"admin"}).role == "admin"
    assert _require_role(support_p, {"admin", "support"}).role == "support"

    with pytest.raises(ForbiddenError, match="insufficient permissions"):
        _require_role(support_p, {"admin"})

    with pytest.raises(ForbiddenError, match="insufficient permissions"):
        _require_role(None, {"admin"})

    mock_pool = MagicMock()
    mock_repo = MagicMock()
    routes = create_limits_routes(pool=mock_pool, limits_repo=mock_repo)
    paths = {r.path for r in routes}
    assert "/admin/agents/{id}/limits" in paths
    assert "/admin/merchants/{merchant_id}/webhooks" in paths
