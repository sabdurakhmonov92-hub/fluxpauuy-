"""Dashboard views, route handlers, and server-rendered HTML presentation (Block L).

=============================================================================
ARCHITECTURAL DESIGN INVARIANTS
=============================================================================

1. ZERO BUSINESS LOGIC:
   Views only perform data orchestration and HTML rendering. They do not alter
   balances, calculate fees, or mutate states outside of existing domain APIs.

2. DIRECT READ-MODEL SQL DEVIATION:
   Repository pattern (AgentRepo, MerchantRepo) strictly enforces domain boundaries
   and write integrity. For read-only operational dashboard screens, views execute
   direct read-model SELECT queries against the database pool. Repositories serve the
   domain; views serve the presentation pages; the double-entry ledger remains the
   sole financial truth.

3. PROGRESSIVE ENHANCEMENT & NO-JS LAW:
   All links and pagination cursors are valid HTML anchor tags (`<a href="...">`).
   The dashboard functions 100% correctly with JavaScript disabled. Vendored htmx
   enhances the user experience with inline swaps when enabled, without breaking
   progressive enhancement.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from fluxpay.dashboard.auth import format_minor
from fluxpay.ledger.postgres import PostgresLedgerStore
from fluxpay.ledger.queries import account_statement
from fluxpay.payments import PRIMARY_CURRENCY
from fluxpay.wallet.accounts import AccountDirectory

__all__ = [
    "TEMPLATES_DIR",
    "router",
    "templates",
]

# Path to template files located at repository root
TEMPLATES_DIR: Path = Path(__file__).resolve().parents[3] / "templates"

templates: Jinja2Templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.filters["format_minor"] = format_minor

router: APIRouter = APIRouter(prefix="/dashboard", tags=["dashboard"])


# -----------------------------------------------------------------------------
# 1. OVERVIEW & AGENT NAVIGATION
# -----------------------------------------------------------------------------


@router.get("", response_class=HTMLResponse)
async def dashboard_root() -> RedirectResponse:
    """Redirect root dashboard path to the agent management overview."""
    return RedirectResponse(url="/dashboard/agents", status_code=302)


@router.get("/agents", response_class=HTMLResponse)
async def list_agents(request: Request) -> HTMLResponse:
    """List all registered autonomous agents for operator inspection."""
    pool: asyncpg.Pool = request.app.state.pool

    # read-model query, repo law N/A for dashboards
    # Documented deviation: repos serve DOMAIN; views serve PAGES; ledger remains money-truth.
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, external_id, name, active, created_at
            FROM agents
            ORDER BY created_at DESC;
            """
        )

    context = {
        "request": request,
        "agents": rows,
        "principal": getattr(request.state, "principal", None),
        "csrf_token": getattr(request.state, "csrf_token", ""),
    }
    return templates.TemplateResponse(request, "agents.html", context)


# -----------------------------------------------------------------------------
# 2. SCREEN 1: AGENT BALANCE & CRYPTOGRAPHICALLY VERIFIED STATEMENT
# -----------------------------------------------------------------------------


@router.get("/agents/{agent_id}", response_class=HTMLResponse)
async def get_agent_statement(
    agent_id: UUID,
    request: Request,
    before_seq: int | None = Query(default=None, ge=1),
) -> HTMLResponse:
    """Screen 1: Balance card, cryptographic proof, and keyset-paginated statement."""
    pool: asyncpg.Pool = request.app.state.pool
    directory: AccountDirectory = request.app.state.directory
    ledger: PostgresLedgerStore = request.app.state.ledger

    # 1. Resolve agent identity
    async with pool.acquire() as conn:
        agent_row = await conn.fetchrow(
            """
            SELECT id, external_id, name, active, created_at
            FROM agents
            WHERE id = $1;
            """,
            agent_id,
        )

    if agent_row is None:
        raise HTTPException(status_code=404, detail="Agent not found.")

    # 2. Resolve agent ledger account and current balance
    account_ref = await directory.get_agent_account(agent_id, PRIMARY_CURRENCY)
    balance = await ledger.get_balance(account_ref.account_id)

    # 3. Calculate 50-entry keyset pagination window (Task 15 / Task 17)
    # Cursor pagination: NO offset pagination.
    window_size = 50
    if before_seq is not None:
        to_seq = max(1, before_seq - 1)
        from_seq = max(1, to_seq - window_size + 1)
    else:
        history = await ledger.get_history(account_ref.account_id, limit=1)
        if history:
            to_seq = history[0].seq
            from_seq = max(1, to_seq - window_size + 1)
        else:
            from_seq = 1
            to_seq = 1

    # 4. Generate cryptographically verified account statement (Task 17)
    statement = await account_statement(
        ledger,
        account_ref.account_id,
        from_seq=from_seq,
        to_seq=to_seq,
    )

    has_older = statement.from_seq > 1
    balance_formatted = format_minor(balance.balance, balance.currency)
    opening_balance_formatted = (
        format_minor(statement.opening_balance, statement.currency)
        if statement.opening_balance is not None
        else "Genesis"
    )
    closing_balance_formatted = (
        format_minor(statement.closing_balance, statement.currency)
        if statement.closing_balance is not None
        else "0.000000"
    )

    context = {
        "request": request,
        "agent": agent_row,
        "account_ref": account_ref,
        "balance": balance,
        "balance_formatted": balance_formatted,
        "statement": statement,
        "opening_balance_formatted": opening_balance_formatted,
        "closing_balance_formatted": closing_balance_formatted,
        "has_older": has_older,
        "before_seq": before_seq,
        "principal": getattr(request.state, "principal", None),
        "csrf_token": getattr(request.state, "csrf_token", ""),
    }
    return templates.TemplateResponse(request, "overview.html", context)


# Mount operational screens and mutation handlers (Task 62)
from fluxpay.dashboard.ops import router as ops_router  # noqa: E402

router.include_router(ops_router)
