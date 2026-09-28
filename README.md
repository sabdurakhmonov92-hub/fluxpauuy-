# FluxPay v3

Payment infrastructure engine designed for autonomous AI agent economies.

## Bootstrap Commands

FluxPay standardizes strictly on `uv` for deterministic dependency resolution and toolchain execution.

```bash
# 1. Install locked runtime and developer dependencies
uv sync

# 2. Execute test suite and verify domain invariants
uv run pytest

# 3. Perform static linting and security analysis
uv run ruff check src tests

# 4. Verify code style and formatting standards
uv run ruff format --check src tests

# 5. Enforce strict static type checking
uv run mypy
```

## Rules of Engagement

1. **Invariant-Tested Money Paths**: Every codepath touching balances, ledgers, transactions, or settlement accepts only invariant-tested code. Unit tests must prove double-entry balance conservation, idempotent retries, and state machine validity before code hits review.
2. **Zero Secrets Outside Environment**: Hardcoded credentials, API keys, private keys, or certificates are strictly forbidden. All secrets must resolve via environment variables managed through `pydantic-settings`.
3. **Downward Dependency Invariant**: Architecture follows a strict modular monolith design across 12 isolated domains (`gateway` down to `shared`). Imports flow strictly downward; lateral imports into a neighboring module's internal implementation details are rejected at lint time.
4. **Strict Quality Gates**: Zero tolerance for unhandled warnings (`filterwarnings = ["error"]`), missing type annotations (`strict = true`), or untested branches (`branch = true`). CI fails if any gate fails.
