"""Unit tests for settlement rail routing and decision models.

Validates:
1. Rail enum freeze: exactly ONE member (INTERNAL="internal") in Phase 1.
2. route() pure function: always returns Rail.INTERNAL with settle_at="immediate".
3. Signature freeze: keyword-only parameters (*, amount_minor, currency).
4. StrictInt & currency grammar validation in routing.
5. RailDecision immutability and slots enforcement.
6. Pure-leaf meta-test: routing.py imports NOTHING from fluxpay.
"""

import ast
import inspect
from dataclasses import FrozenInstanceError, is_dataclass
from pathlib import Path
from typing import Any

import pytest

from fluxpay.payments.routing import (
    Rail,
    RailDecision,
    route,
)

pytestmark = pytest.mark.unit


# ==============================================================================
# 1. Rail Enum Freeze (Phase 1 Invariant)
# ==============================================================================


def test_rail_enum_has_exactly_one_member_freeze_proof() -> None:
    """Freeze-proof: Rail enum MUST have exactly ONE member (INTERNAL) in Phase 1.

    External rails (Base L2, Stripe, etc.) are strictly Phase 2 additions.
    Verifying that Rail has only INTERNAL prevents accidental rail proliferation
    before adapter infrastructure (Tasks 49-50) is ready.
    """
    assert len(Rail) == 1, (
        f"Rail enum has {len(Rail)} members; expected exactly 1 (INTERNAL) in Phase 1"
    )
    assert list(Rail) == [Rail.INTERNAL]
    assert Rail.INTERNAL.value == "internal"
    assert str(Rail.INTERNAL) == "internal"
    assert Rail("internal") is Rail.INTERNAL


# ==============================================================================
# 2. route() Always Returns Internal Immediate (Phase 1 Seam)
# ==============================================================================


def test_route_always_returns_internal_immediate() -> None:
    """Validate route() returns RailDecision(rail=Rail.INTERNAL, settle_at='immediate')."""
    decision = route(amount_minor=50_000, currency="USDC")
    assert isinstance(decision, RailDecision)
    assert decision.rail is Rail.INTERNAL
    assert decision.rail == Rail.INTERNAL
    assert decision.settle_at == "immediate"


@pytest.mark.parametrize(
    ("amount_minor", "currency"),
    [
        (1_000, "USDC"),
        (10_000_000, "USD"),
        (100_000_000_000, "EUR"),
        (5_000, "BTC"),
    ],
)
def test_route_various_valid_amounts_and_currencies(amount_minor: int, currency: str) -> None:
    """Validate route succeeds for any valid positive amount and compliant currency."""
    decision = route(amount_minor=amount_minor, currency=currency)
    assert decision.rail is Rail.INTERNAL
    assert decision.settle_at == "immediate"


# ==============================================================================
# 3. Keyword-Only Signature Freeze
# ==============================================================================


def test_route_signature_is_keyword_only() -> None:
    """Validate route() enforces keyword-only arguments (*, amount_minor, currency).

    Positional arguments MUST be rejected by Python's calling convention to freeze
    the calling contract for Task 31 service orchestration.
    """
    # 1. Positional invocation raises TypeError
    with pytest.raises(TypeError):
        route(1_000, "USDC")  # type: ignore[misc]

    # 2. Parameter reflection verification
    sig = inspect.signature(route)
    params = list(sig.parameters.values())

    assert len(params) == 2
    assert {p.name for p in params} == {"amount_minor", "currency"}
    for p in params:
        assert p.kind == inspect.Parameter.KEYWORD_ONLY, (
            f"Parameter '{p.name}' must be KEYWORD_ONLY, got {p.kind}"
        )


# ==============================================================================
# 4. StrictInt & Grammar Validation
# ==============================================================================


def test_route_rejects_boolean_amounts() -> None:
    """Validate boolean amounts are rejected under StrictInt philosophy."""
    with pytest.raises(ValueError, match="bool rejected"):
        route(amount_minor=True, currency="USDC")

    with pytest.raises(ValueError, match="bool rejected"):
        route(amount_minor=False, currency="USDC")


@pytest.mark.parametrize("invalid_amount", [0, -1, -5000])
def test_route_rejects_non_positive_amounts(invalid_amount: int) -> None:
    """Validate non-positive amounts raise ValueError."""
    with pytest.raises(ValueError, match="must be a positive integer > 0"):
        route(amount_minor=invalid_amount, currency="USDC")


@pytest.mark.parametrize("invalid_type", [1000.5, "1000", None, [1000]])
def test_route_rejects_non_integer_types(invalid_type: Any) -> None:
    """Validate floats, strings, and non-ints raise ValueError."""
    with pytest.raises(ValueError, match="must be a positive integer > 0"):
        route(amount_minor=invalid_type, currency="USDC")


@pytest.mark.parametrize(
    "invalid_currency",
    [
        "",  # Empty
        "U",  # Too short
        "TOOLONGCURRENCY",  # >10 chars
        "usdc",  # Lowercase
        "USDC-PAY",  # Special character
        "US DC",  # Space
    ],
)
def test_route_rejects_invalid_currency_grammar(invalid_currency: str) -> None:
    """Validate currency not matching ^[A-Z0-9]{2,10}$ raises ValueError."""
    with pytest.raises(ValueError, match="currency: must match regex"):
        route(amount_minor=1_000, currency=invalid_currency)


def test_route_rejects_non_string_currency() -> None:
    """Validate non-string currency raises ValueError."""
    with pytest.raises(ValueError, match="currency: must match regex"):
        route(amount_minor=1_000, currency=123)  # type: ignore[arg-type]


# ==============================================================================
# 5. RailDecision Immutability & Slots
# ==============================================================================


def test_rail_decision_is_frozen_slots_dataclass() -> None:
    """Validate RailDecision is an immutable frozen dataclass with slots."""
    assert is_dataclass(RailDecision)
    assert hasattr(RailDecision, "__slots__")

    decision = route(amount_minor=1_000, currency="USDC")
    with pytest.raises(FrozenInstanceError):
        decision.rail = Rail.INTERNAL  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        decision.settle_at = "immediate"  # type: ignore[misc]


def test_rail_decision_construction_validates_invariants() -> None:
    """Validate RailDecision.__post_init__ prevents invalid construction."""
    # Rail must be instance of Rail enum
    with pytest.raises(ValueError, match="rail must be an instance of Rail enum"):
        RailDecision(rail="internal", settle_at="immediate")  # type: ignore[arg-type]

    # settle_at must be 'immediate' in Phase 1
    with pytest.raises(ValueError, match="settle_at must be 'immediate'"):
        RailDecision(rail=Rail.INTERNAL, settle_at="wait_finality")  # type: ignore[arg-type]


# ==============================================================================
# 6. Pure Leaf Meta-Test (Import Blacklist)
# ==============================================================================


def test_routing_is_pure_leaf_with_no_fluxpay_imports() -> None:
    """Contract enforcement: routing.py must NOT import anything from fluxpay.

    Pure leaf module law (Task 12 discipline):
    - Currency grammar is mirrored, not imported.
    - Rail types and routing logic are pure and standalone.
    """
    repo_root = Path(__file__).resolve().parents[2]
    routing_path = repo_root / "src" / "fluxpay" / "payments" / "routing.py"
    assert routing_path.is_file(), f"routing.py not found at {routing_path}"

    tree = ast.parse(routing_path.read_text(encoding="utf-8"))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("fluxpay"), (
                    f"routing.py violates pure leaf law: imports '{alias.name}'"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert not node.module.startswith("fluxpay"), (
                    f"routing.py violates pure leaf law: imports from '{node.module}'"
                )
