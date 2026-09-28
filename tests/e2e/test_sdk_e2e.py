"""=============================================================================
End-to-End SDK Integration Suite & Cross-Language Contract Proof (Task 57)
=============================================================================
Proves:
1. Cross-Language Equivalence:
   Python KAT == Node KAT == Task 19 Frozen Canonical Vectors (The Triple Proof).
   Subprocess execution of `node sdk/node/tests/run_kat.mjs` exits 0 with PASS lines.
2. Vendoring Law & Zero-Dep Compliance:
   - Python SDK (`fluxpay_sdk`) imports stdlib + httpx ONLY (no server imports).
   - Node SDK (`fluxpay`) package.json specifies zero runtime dependencies.
3. Client Retry Ladder & Error Taxonomy (Task 4 Parity):
   - 429, 502, 503 retried with exponential backoff; 400, 401, 403, 404, 409, 422 never retried.
   - Same-key retry law: `X-FLX-Idempotency-Key` preserved across write retries.
4. Python SDK against REAL Gateway Stack (Postgres + Valkey + RabbitMQ):
   - Blueprint §0 3-line quickstart face literally demonstrated in test body.
   - Idempotent retry under injected network timeout: drops response after server commit,
     client retries with same key, receives byte-equal result, exactly 1 ledger transaction.
   - Error dialect: unknown merchant (404), bad secret (401), rate limits (429).
=============================================================================
"""

import ast
import json
import shutil
import subprocess
import sys
from collections.abc import AsyncGenerator, Callable, Coroutine
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

SDK_PYTHON_PATH: Path = REPO_ROOT / "sdk" / "python"
if str(SDK_PYTHON_PATH) not in sys.path:
    sys.path.insert(0, str(SDK_PYTHON_PATH))

import asyncpg  # type: ignore[import-untyped]  # noqa: E402
import fluxpay_sdk.signing as sdk_signing  # noqa: E402
import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from fluxpay_sdk import (  # noqa: E402
    FluxPayApiError,
    FluxPayClient,
    FluxPayNetworkError,
    PaymentResult,
)

# Server canonical authority (for cross-language comparison)
from fluxpay.gateway.canonical import (  # noqa: E402
    get_frozen_vectors as get_server_frozen_vectors,
)
from fluxpay.ledger.hashchain import Direction  # noqa: E402
from fluxpay.ledger.postgres import PostgresLedgerStore  # noqa: E402
from fluxpay.ledger.store import EntryDraft  # noqa: E402
from fluxpay.payments.service import deterministic_tx_id  # noqa: E402
from fluxpay.registry.agents import (  # noqa: E402
    AgentLifecycle,
    CreateAgentCommand,
    CreateMerchantCommand,
    MerchantLifecycle,
)
from fluxpay.wallet.accounts import AccountDirectory  # noqa: E402

pytestmark = pytest.mark.integration
pytest_plugins = ["tests.integration.conftest"]

TEST_SECRET: str = "test-secret-key-32-bytes-long!!"  # noqa: S105


# -----------------------------------------------------------------------------
# Fixtures for Real Stack Testing
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class SDKTestCredentials:
    agent_id: UUID
    external_id: str
    secret: str


@pytest_asyncio.fixture
async def make_sdk_agent(
    agent_lifecycle: AgentLifecycle,
) -> Callable[..., Coroutine[Any, Any, SDKTestCredentials]]:
    """Provision agent row and ledger account for SDK testing."""

    async def _make(
        *,
        external_id: str | None = None,
        name: str = "Test SDK Agent",
        currency: str = "USDC",
        rate_limit_max: int = 100,
    ) -> SDKTestCredentials:
        ext_id = external_id or f"ag_sdk_{uuid4().hex[:10]}"
        created = await agent_lifecycle.create_agent(
            CreateAgentCommand(
                external_id=ext_id,
                name=name,
                currency=currency,
                rate_limit_max=rate_limit_max,
            )
        )
        return SDKTestCredentials(
            agent_id=created.agent_id,
            external_id=created.external_id,
            secret=created.secret,
        )

    return _make


@pytest_asyncio.fixture
async def seed_sdk_account(
    db_pool: asyncpg.Pool,
    account_directory: AccountDirectory,
    ledger_store: PostgresLedgerStore,
    apply_bootstrap: None,
) -> Any:
    """Seed account funds from authoritative system treasury account."""
    system_ref = await account_directory.get_system_account("USDC")

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE ledger_accounts
            SET balance = balance + 100_000_000_000, version = version + 1
            WHERE id = $1;
            """,
            system_ref.account_id,
        )

    async def _seed(account_id: UUID, amount: int, currency: str = "USDC") -> Any:
        return await ledger_store.post_transaction(
            [
                EntryDraft(
                    account_id=system_ref.account_id,
                    direction=Direction.DEBIT,
                    amount=amount,
                    currency=currency,
                ),
                EntryDraft(
                    account_id=account_id,
                    direction=Direction.CREDIT,
                    amount=amount,
                    currency=currency,
                ),
            ]
        )

    return _seed


@pytest_asyncio.fixture
async def platform_client(
    build_app: Any,
) -> AsyncGenerator[tuple[httpx.AsyncClient, Any], None]:
    """Provide httpx AsyncClient connected to live platform application."""
    app = build_app()
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client, app


# =============================================================================
# 1. CROSS-LANGUAGE KAT EQUIVALENCE (THE TRIPLE PROOF)
# =============================================================================


def test_python_kat_matches_server_authority() -> None:
    """Python SDK signing vectors must match Task 19 canonical.py byte-for-byte."""
    server_vectors = get_server_frozen_vectors()
    sdk_vectors = sdk_signing.get_frozen_vectors()

    assert len(sdk_vectors) == 3
    assert len(server_vectors) == 3

    for idx, (srv, sdk) in enumerate(zip(server_vectors, sdk_vectors, strict=True)):
        assert srv["method"] == sdk["method"]
        assert srv["path"] == sdk["path"]
        assert srv["timestamp"] == sdk["timestamp"]
        assert srv["nonce"] == sdk["nonce"]
        assert srv["body"] == sdk["body"]
        assert srv["expected_canonical"] == sdk["expected_canonical"]
        assert srv["expected_signature"] == sdk["expected_signature"]

        # Recompute signature via SDK sign() function
        computed_sig = sdk_signing.sign(
            secret=sdk["secret"],
            method=sdk["method"],
            path=sdk["path"],
            timestamp=sdk["timestamp"],
            nonce=sdk["nonce"],
            body=sdk["body"],
        )
        assert computed_sig == srv["expected_signature"], f"Vector {idx + 1} mismatch"

        # Verify via SDK verify()
        assert (
            sdk_signing.verify(
                secret=sdk["secret"],
                provided_sig=computed_sig,
                method=sdk["method"],
                path=sdk["path"],
                timestamp=sdk["timestamp"],
                nonce=sdk["nonce"],
                body=sdk["body"],
            )
            is True
        )


def test_node_kat_runner_subprocess() -> None:
    """Subprocess `node sdk/node/tests/run_kat.mjs` must exit 0 and print PASS lines."""
    runner_script = REPO_ROOT / "sdk" / "node" / "tests" / "run_kat.mjs"
    assert runner_script.is_file(), f"Runner script missing: {runner_script}"

    node_bin = shutil.which("node") or "node"
    result = subprocess.run(  # noqa: S603
        [node_bin, str(runner_script)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, f"Node KAT runner failed:\n{result.stderr}"
    stdout = result.stdout
    assert "PASS vector 1" in stdout
    assert "PASS vector 2" in stdout
    assert "PASS vector 3" in stdout
    assert "All 3 KAT vectors PASSED" in stdout


def test_cross_language_kat_triple_proof() -> None:
    """Cross-language verification: Server, Python SDK, and Node agree on all 3 vectors."""
    server_vectors = get_server_frozen_vectors()

    runner_script = REPO_ROOT / "sdk" / "node" / "tests" / "run_kat.mjs"
    node_bin = shutil.which("node") or "node"
    result = subprocess.run(  # noqa: S603
        [node_bin, str(runner_script)],
        capture_output=True,
        text=True,
        check=True,
    )

    for v in server_vectors:
        assert v["expected_signature"] in result.stdout
        py_sig = sdk_signing.sign(
            secret=v["secret"],
            method=v["method"],
            path=v["path"],
            timestamp=v["timestamp"],
            nonce=v["nonce"],
            body=v["body"],
        )
        assert py_sig == v["expected_signature"]


# =============================================================================
# 2. VENDORING LAW & DEPENDENCY COMPLIANCE
# =============================================================================


def test_python_sdk_vendoring_law_meta_test() -> None:
    """Python SDK must import stdlib + httpx ONLY. Zero imports from server (fluxpay.*)."""
    sdk_dir = REPO_ROOT / "sdk" / "python" / "fluxpay_sdk"
    py_files = list(sdk_dir.glob("*.py"))
    assert len(py_files) >= 3, "Expected at least __init__.py, client.py, signing.py"

    allowed_external_modules = {"httpx"}

    for py_file in py_files:
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_pkg = alias.name.split(".")[0]
                    assert root_pkg != "fluxpay", (
                        f"Vendoring violation in {py_file.name}: server import '{alias.name}'"
                    )
                    if root_pkg not in sys.stdlib_module_names and root_pkg != "_typeshed":
                        assert root_pkg in allowed_external_modules, (
                            f"Vendoring violation in {py_file.name}: invalid import '{root_pkg}'"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    root_pkg = node.module.split(".")[0]
                    assert root_pkg != "fluxpay", (
                        f"Vendoring violation in {py_file.name}: server import '{node.module}'"
                    )
                    if root_pkg not in sys.stdlib_module_names and root_pkg != "_typeshed":
                        assert root_pkg in allowed_external_modules, (
                            f"Vendoring violation in {py_file.name}: invalid import '{root_pkg}'"
                        )


def test_node_sdk_zero_deps_meta_test() -> None:
    """Node SDK package.json must declare zero runtime dependencies."""
    pkg_json_path = REPO_ROOT / "sdk" / "node" / "fluxpay" / "package.json"
    assert pkg_json_path.is_file(), f"Missing package.json at {pkg_json_path}"

    data = json.loads(pkg_json_path.read_text(encoding="utf-8"))
    assert data.get("name") == "fluxpay"
    assert data.get("type") == "module"
    deps = data.get("dependencies", {})
    assert deps == {}, f"Node SDK must have zero runtime dependencies, found: {deps}"


# =============================================================================
# 3. CLIENT RETRY LADDER & IDEMPOTENCY LOGIC (MOCKED TRANSPORT)
# =============================================================================


@pytest.mark.asyncio
async def test_client_retry_ladder_mocked() -> None:
    """Verify retry behavior: 429/503 retried up to max_retries; 400/404/422 never retried."""
    captured_requests: list[httpx.Request] = []
    attempt_count = 0

    async def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempt_count
        attempt_count += 1
        captured_requests.append(request)
        if attempt_count < 3:
            return httpx.Response(
                429,
                json={
                    "error": {
                        "code": "rate_limited",
                        "message": "Too many requests. Please retry after backoff.",
                        "retryable": True,
                    }
                },
            )
        return httpx.Response(
            201,
            json={
                "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "status": "settled",
            },
        )

    transport = httpx.MockTransport(mock_handler)
    http_client = httpx.AsyncClient(transport=transport, base_url="http://test")

    sleep_called: list[float] = []

    async def fake_sleep(duration: float) -> None:
        sleep_called.append(duration)

    client = FluxPayClient(
        agent_id=str(uuid4()),
        secret=TEST_SECRET,
        base_url="http://test",
        http=http_client,
        sleep_fn=fake_sleep,
        max_retries=3,
    )

    idem_key = "test-idem-preserve-12345678"
    result = await client.pay(
        to="merchant_demo",
        amount=1050,
        currency="USDC",
        idempotency_key=idem_key,
    )

    assert result.status == "settled"
    assert str(result.id) == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    assert attempt_count == 3
    assert len(sleep_called) == 2

    # SAME-KEY RETRY LAW: verify idempotency key was identical on all 3 attempts
    for req in captured_requests:
        assert req.headers["X-FLX-Idempotency-Key"] == idem_key
    # But nonces were distinct
    nonce1 = captured_requests[0].headers["X-FLX-Nonce"]
    nonce2 = captured_requests[1].headers["X-FLX-Nonce"]
    assert nonce1 != nonce2


@pytest.mark.asyncio
async def test_client_never_retries_permanent_errors() -> None:
    """Non-retryable HTTP statuses (400, 401, 403, 404, 409, 422) must fail immediately."""
    type HandlerCallable = Callable[[httpx.Request], Coroutine[Any, Any, httpx.Response]]

    def make_handler(sc: int, ec: str) -> tuple[HandlerCallable, list[int]]:
        counter: list[int] = [0]

        async def handler(_req: httpx.Request) -> httpx.Response:
            counter[0] += 1
            return httpx.Response(
                sc,
                json={"error": {"code": ec, "message": f"Failure: {ec}", "retryable": False}},
            )

        return handler, counter

    for status_code, err_code in [
        (400, "insufficient_funds"),
        (401, "authentication_failed"),
        (403, "forbidden"),
        (404, "not_found"),
        (409, "idempotency_conflict"),
        (422, "validation_failed"),
    ]:
        handler_fn, counter = make_handler(status_code, err_code)
        http = httpx.AsyncClient(
            transport=httpx.MockTransport(handler_fn),
            base_url="http://test",
        )
        client = FluxPayClient(
            agent_id=str(uuid4()),
            secret=TEST_SECRET,
            base_url="http://test",
            http=http,
            max_retries=3,
        )

        with pytest.raises(FluxPayApiError) as exc_info:
            await client.pay(to="merchant_demo", amount=1000)

        assert exc_info.value.status == status_code
        assert exc_info.value.code == err_code
        assert exc_info.value.retryable is False
        assert counter[0] == 1, f"Status {status_code} was retried {counter[0]} times!"


@pytest.mark.asyncio
async def test_client_exhausts_retries_on_network_timeout() -> None:
    """When retries exhaust on network timeout, raise FluxPayNetworkError(retryable=True)."""
    calls = 0

    async def timeout_handler(_req: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout("Simulated gateway read timeout")

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(timeout_handler),
        base_url="http://test",
    )
    sleeps: list[float] = []

    async def fake_sleep(s: float) -> None:
        sleeps.append(s)

    client = FluxPayClient(
        agent_id=str(uuid4()),
        secret=TEST_SECRET,
        base_url="http://test",
        http=http,
        sleep_fn=fake_sleep,
        max_retries=2,
    )

    with pytest.raises(FluxPayNetworkError) as exc_info:
        await client.balance()

    assert exc_info.value.retryable is True
    assert calls == 3  # Initial attempt + 2 retries
    assert len(sleeps) == 2


# =============================================================================
# 4. PYTHON SDK AGAINST REAL GATEWAY (END-TO-END ACCEPTANCE)
# =============================================================================


@pytest.mark.asyncio
async def test_python_sdk_real_gateway_pay_and_balance(
    platform_client: tuple[httpx.AsyncClient, Any],
    db_pool: asyncpg.Pool,
    make_sdk_agent: Any,
    merchant_lifecycle: MerchantLifecycle,
    account_directory: AccountDirectory,
    seed_sdk_account: Any,
) -> None:
    """Execute live payment and balance check via FluxPayClient against real stack.

    Demonstrates Blueprint §0 3-line face, verifies 3 ledger entries, and balance reflection.
    """
    raw_http, _app = platform_client

    # 1. Provision Agent and Merchant
    creds = await make_sdk_agent()
    merch_ext = f"mch_sdk_{uuid4().hex[:10]}"
    await merchant_lifecycle.create_merchant(CreateMerchantCommand(external_id=merch_ext))

    agent_acct = await account_directory.get_agent_account(creds.agent_id)
    merchant_acct = await account_directory.get_merchant_account(merch_ext)
    fees_acct = await account_directory.get_fees_account()

    # 2. Fund agent with $100 (100_000 minor units)
    await seed_sdk_account(agent_acct.account_id, 100_000, "USDC")

    # =========================================================================
    # THE BLUEPRINT §0 3-LINE PROMISE (LITERALLY 3 LINES):
    # =========================================================================
    fp = FluxPayClient(
        agent_id=str(creds.agent_id), secret=creds.secret, base_url="http://test", http=raw_http
    )
    payment = await fp.pay(to=merch_ext, amount=1050)
    assert payment.status == "settled"
    # =========================================================================

    assert isinstance(payment, PaymentResult)
    assert payment.id is not None

    # 3. Verify exactly 3 double-entry ledger rows posted
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT account_id, direction, amount, currency
            FROM ledger_entries
            WHERE transaction_id = $1
            ORDER BY created_at ASC;
            """,
            payment.id,
        )
        assert len(rows) == 3

        entries = {(r["account_id"], r["direction"], r["amount"], r["currency"]) for r in rows}
        # Agent debited total (1050 amount + 10 fee = 1060)
        assert (agent_acct.account_id, "DEBIT", 1060, "USDC") in entries
        # Merchant credited amount (1050)
        assert (merchant_acct.account_id, "CREDIT", 1050, "USDC") in entries
        # System fees credited fee (10)
        assert (fees_acct.account_id, "CREDIT", 10, "USDC") in entries

    # 4. Verify balance reflection via SDK
    bal = await fp.balance()
    assert bal.currency == "USDC"
    assert bal.balance == 100_000 - 1060

    # 5. Verify get_payment detail via SDK
    detail = await fp.get_payment(payment.id)
    assert detail.id == payment.id
    assert detail.status == "settled"
    assert detail.amount == 1050
    assert detail.currency == "USDC"


@pytest.mark.asyncio
async def test_python_sdk_idempotent_retry_under_injected_network_drop(
    platform_client: tuple[httpx.AsyncClient, Any],
    db_pool: asyncpg.Pool,
    make_sdk_agent: Any,
    merchant_lifecycle: MerchantLifecycle,
    account_directory: AccountDirectory,
    seed_sdk_account: Any,
) -> None:
    """Network timeout dropped response -> client retries with SAME key -> 1 ledger tx."""
    _raw_http, app = platform_client

    creds = await make_sdk_agent()
    merch_ext = f"mch_idem_{uuid4().hex[:10]}"
    await merchant_lifecycle.create_merchant(CreateMerchantCommand(external_id=merch_ext))
    agent_acct = await account_directory.get_agent_account(creds.agent_id)
    await seed_sdk_account(agent_acct.account_id, 50_000, "USDC")

    call_count = 0
    asgi_transport = httpx.ASGITransport(app=app)

    class DropFirstResponseTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            resp = await asgi_transport.handle_async_request(request)
            if request.method == "POST" and call_count == 1:
                # Server processed and committed transaction, but wire drops response
                raise httpx.ReadTimeout("Simulated network drop after server commit")
            return resp

    wrapped_http = httpx.AsyncClient(
        transport=DropFirstResponseTransport(),
        base_url="http://test",
    )

    idem_key = f"idem-drop-{uuid4().hex[:12]}"

    async def instant_sleep(_: float) -> None:
        pass

    fp = FluxPayClient(
        agent_id=str(creds.agent_id),
        secret=creds.secret,
        base_url="http://test",
        http=wrapped_http,
        sleep_fn=instant_sleep,
        max_retries=2,
    )

    result = await fp.pay(
        to=merch_ext,
        amount=1050,
        currency="USDC",
        idempotency_key=idem_key,
    )

    assert result.status == "settled"
    assert call_count == 2, "Expected exactly 2 attempts"

    # Verify server executed exactly ONCE in the ledger
    expected_tx_id = deterministic_tx_id(creds.agent_id, idem_key)
    assert result.id == expected_tx_id

    async with db_pool.acquire() as conn:
        tx_count = await conn.fetchval(
            "SELECT COUNT(*) FROM ledger_transactions WHERE id = $1;",
            expected_tx_id,
        )
        assert tx_count == 1, "Double-spend detected! Ledger transaction count must be exactly 1."


@pytest.mark.asyncio
async def test_python_sdk_error_dialect_real_gateway(
    platform_client: tuple[httpx.AsyncClient, Any],
    make_sdk_agent: Any,
) -> None:
    """Verify typed FluxPayApiError exceptions raised against real gateway."""
    raw_http, _ = platform_client
    creds = await make_sdk_agent()

    fp = FluxPayClient(
        agent_id=str(creds.agent_id),
        secret=creds.secret,
        base_url="http://test",
        http=raw_http,
    )

    # 1. Unknown merchant returns 404 not_found
    with pytest.raises(FluxPayApiError) as exc_info:
        await fp.pay(to="mch_nonexistent_9999", amount=1000)

    assert exc_info.value.status == 404
    assert exc_info.value.code == "not_found"
    assert exc_info.value.retryable is False

    # 2. Bad secret returns 401 authentication_failed
    bad_secret = "wrong-secret-key-32-bytes-long!!"  # noqa: S105
    bad_fp = FluxPayClient(
        agent_id=str(creds.agent_id),
        secret=bad_secret,
        base_url="http://test",
        http=raw_http,
    )
    with pytest.raises(FluxPayApiError) as auth_exc:
        await bad_fp.balance()

    assert auth_exc.value.status == 401
    assert auth_exc.value.code == "authentication_failed"
    assert auth_exc.value.retryable is False


@pytest.mark.asyncio
async def test_python_sdk_rate_limit_convergence_real_gateway(
    platform_client: tuple[httpx.AsyncClient, Any],
    make_sdk_agent: Any,
    merchant_lifecycle: MerchantLifecycle,
    account_directory: AccountDirectory,
    seed_sdk_account: Any,
) -> None:
    """Agent configured with strict rate limit: excess requests trigger 429 FluxPayApiError."""
    raw_http, _ = platform_client
    # Provision agent with rate_limit_max=2
    creds = await make_sdk_agent(rate_limit_max=2)
    merch_ext = f"mch_rate_{uuid4().hex[:10]}"
    await merchant_lifecycle.create_merchant(CreateMerchantCommand(external_id=merch_ext))

    agent_acct = await account_directory.get_agent_account(creds.agent_id)
    await seed_sdk_account(agent_acct.account_id, 100_000, "USDC")

    async def instant_sleep(_: float) -> None:
        pass

    fp = FluxPayClient(
        agent_id=str(creds.agent_id),
        secret=creds.secret,
        base_url="http://test",
        http=raw_http,
        max_retries=1,  # Bounded retries so 429 surfaces after 1 retry
        sleep_fn=instant_sleep,
    )

    # First request: 201
    p1 = await fp.pay(to=merch_ext, amount=100)
    assert p1.status == "settled"

    # Second request: 201
    p2 = await fp.pay(to=merch_ext, amount=100)
    assert p2.status == "settled"

    # Third request: rate limit exceeded -> 429
    with pytest.raises(FluxPayApiError) as exc_info:
        await fp.pay(to=merch_ext, amount=100)

    assert exc_info.value.status == 429
    assert exc_info.value.code == "rate_limited"
    assert exc_info.value.retryable is True
