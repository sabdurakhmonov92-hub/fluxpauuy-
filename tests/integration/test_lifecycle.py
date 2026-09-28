"""Integration tests for Agent and Merchant Lifecycle and Account Directory.

Blueprint §0 Dashboard Rule & §1 Third-Party Merchants & §5 Account Topology.
Blueprint §7 Registry Lifecycle.
Task 27 DoD:
- Atomic agent + ledger_accounts creation (orphan-proof)
- One-time plaintext secret custody & custody chain verification
- Duplicate external_id atomicity witness (zero orphan rows)
- Atomic merchant provisioning (no secret in CreatedMerchant)
- Invalidation through stack on suspend_merchant and activate_agent
- Bootstrap seed idempotency and UUIDv5 determinism proof
- AccountDirectory lookups, in-process fees cache, and LookupError alarms
- No plaintext secrets in DB (vault envelope only)
"""

from __future__ import annotations

import re
import uuid
from typing import Any

import asyncpg  # type: ignore[import-untyped]
import pytest

from fluxpay.gateway import canonical
from fluxpay.registry.agents import (
    AgentLifecycle,
    CreateAgentCommand,
    CreateMerchantCommand,
    MerchantLifecycle,
)
from fluxpay.registry.merchants import MerchantRepo
from fluxpay.registry.repo import AgentRepo, agent_secret_context
from fluxpay.shared.vault import SecretBytes, encrypt_secret
from fluxpay.wallet.accounts import (
    FEES_OWNER_ID,
    FLXPAY_NAMESPACE_UUID,
    SYSTEM_OWNER_ID,
    TREASURY_OWNER_ID,
    AccountDirectory,
    reset_fees_cache,
)

pytestmark = pytest.mark.integration


# -----------------------------------------------------------------------------
# 1. AGENT PROVISIONING & ONE-TIME SECRET CUSTODY TESTS
# -----------------------------------------------------------------------------


async def test_create_agent_happy_path(
    db_pool: asyncpg.Pool,
    agent_lifecycle: AgentLifecycle,
    agent_repo: AgentRepo,
    delete_agent_cascade: Any,
) -> None:
    """Agent provisioning creates agents row and ledger_accounts row in one UoW.

    CreatedAgent returns a 64-hex plaintext secret, which can sign canonical requests
    and verify successfully against AgentRepo.resolve().
    """
    ext_id = f"agt_{uuid.uuid4().hex[:12]}"
    cmd = CreateAgentCommand(
        external_id=ext_id,
        name="  Trading Bot Alpha  ",
        currency="USDC",
        rate_limit_max=50,
        daily_quota_max=5000,
    )

    created = await agent_lifecycle.create_agent(cmd)
    try:
        assert isinstance(created.agent_id, uuid.UUID)
        assert created.external_id == ext_id
        # Secret is 64 lowercase hex chars (256-bit entropy)
        assert len(created.secret) == 64
        assert re.fullmatch(r"^[0-9a-f]{64}$", created.secret)

        # Authoritative PostgreSQL verification: agents row
        async with db_pool.acquire() as conn:
            agent_row = await conn.fetchrow("SELECT * FROM agents WHERE id = $1;", created.agent_id)
            assert agent_row is not None
            assert agent_row["external_id"] == ext_id
            assert agent_row["name"] == "Trading Bot Alpha"  # Stripped
            assert agent_row["active"] is True
            assert agent_row["rate_limit_max"] == 50
            assert agent_row["daily_quota_max"] == 5000
            assert agent_row["version"] == 1
            # Envelope is NOT the plaintext secret
            assert agent_row["secret_encrypted"] != created.secret

            # Authoritative PostgreSQL verification: ledger_accounts row
            acct_row = await conn.fetchrow(
                "SELECT * FROM ledger_accounts WHERE owner_type = 'agent' AND owner_id = $1;",
                created.agent_id,
            )
            assert acct_row is not None
            assert acct_row["currency"] == "USDC"
            assert acct_row["balance"] == 0
            assert acct_row["version"] == 0

        # Full custody chain verification: canonical sign + AgentRepo.resolve + verify
        resolved = await agent_repo.resolve(created.agent_id)
        assert resolved is not None
        assert resolved.agent_id == created.agent_id
        assert resolved.external_id == ext_id
        assert isinstance(resolved.secret, SecretBytes)
        assert bytes(resolved.secret) == created.secret.encode("utf-8")

        # Canonical request signing and verification
        timestamp = "1700000000000"
        nonce = "clientnonce0123456789"
        body = b'{"action":"ping"}'
        sig = canonical.sign(
            secret=created.secret.encode("utf-8"),
            method="POST",
            path="/api/v1/payments",
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        )
        assert len(sig) == 64

        verified = canonical.verify(
            secret=resolved.secret,
            provided_sig=sig,
            method="POST",
            path="/api/v1/payments",
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        )
        assert verified is True
    finally:
        await delete_agent_cascade(created.agent_id)


async def test_one_time_custody_and_envelope_properties(
    db_pool: asyncpg.Pool,
    agent_lifecycle: AgentLifecycle,
    agent_repo: AgentRepo,
    delete_agent_cascade: Any,
) -> None:
    """One-time custody proof: resolve() returns SecretBytes decrypted from vault envelope.

    Encrypting the same plaintext secret again produces a DIFFERENT ciphertext
    due to NIST SP 800-38D random 96-bit nonce uniqueness per encryption.
    """
    ext_id = f"agt_{uuid.uuid4().hex[:12]}"
    created = await agent_lifecycle.create_agent(CreateAgentCommand(external_id=ext_id))
    try:
        resolved = await agent_repo.resolve(created.agent_id)
        assert resolved is not None
        # SecretBytes object in memory, not the same string instance
        assert isinstance(resolved.secret, SecretBytes)
        assert isinstance(created.secret, str)
        assert bytes(resolved.secret) == created.secret.encode("utf-8")

        # Fetch stored envelope from DB
        async with db_pool.acquire() as conn:
            stored_envelope = await conn.fetchval(
                "SELECT secret_encrypted FROM agents WHERE id = $1;", created.agent_id
            )

        # Nonce uniqueness: encrypting same secret again yields a distinct envelope
        re_encrypted = encrypt_secret(
            created.secret,
            context=agent_secret_context(ext_id),
        )
        assert re_encrypted != stored_envelope
    finally:
        await delete_agent_cascade(created.agent_id)


async def test_duplicate_external_id_atomicity_witness(
    db_pool: asyncpg.Pool,
    agent_lifecycle: AgentLifecycle,
    delete_agent_cascade: Any,
) -> None:
    """Atomicity witness: duplicate-create leaves ZERO orphan rows in BOTH tables."""
    ext_id = f"agt_{uuid.uuid4().hex[:12]}"
    created = await agent_lifecycle.create_agent(CreateAgentCommand(external_id=ext_id))
    try:
        async with db_pool.acquire() as conn:
            agent_count_before = await conn.fetchval(
                "SELECT count(*) FROM agents WHERE external_id = $1;", ext_id
            )
            acct_count_before = await conn.fetchval(
                """
                SELECT count(*) FROM ledger_accounts
                WHERE owner_type = 'agent' AND owner_id = $1;
                """,
                created.agent_id,
            )

        # Attempt to provision duplicate external_id
        with pytest.raises(ValueError, match="external_id already registered"):
            await agent_lifecycle.create_agent(CreateAgentCommand(external_id=ext_id))

        # Assert BOTH table counts remain unchanged
        async with db_pool.acquire() as conn:
            agent_count_after = await conn.fetchval(
                "SELECT count(*) FROM agents WHERE external_id = $1;", ext_id
            )
            acct_count_after = await conn.fetchval(
                """
                SELECT count(*) FROM ledger_accounts
                WHERE owner_type = 'agent' AND owner_id = $1;
                """,
                created.agent_id,
            )

        assert agent_count_before == agent_count_after == 1
        assert acct_count_before == acct_count_after == 1
    finally:
        await delete_agent_cascade(created.agent_id)


async def test_create_agent_validation_errors(
    agent_lifecycle: AgentLifecycle,
) -> None:
    """Domain validation errors raise ValueError with field names before database interaction."""
    # Invalid external_id grammar
    with pytest.raises(ValueError, match="external_id"):
        await agent_lifecycle.create_agent(CreateAgentCommand(external_id="ab"))  # Too short

    with pytest.raises(ValueError, match="external_id"):
        await agent_lifecycle.create_agent(CreateAgentCommand(external_id="has UPPERCASE"))

    # Name too long
    with pytest.raises(ValueError, match="name"):
        await agent_lifecycle.create_agent(
            CreateAgentCommand(external_id="agt_valid", name="x" * 129)
        )

    # Invalid currency
    with pytest.raises(ValueError, match="currency"):
        await agent_lifecycle.create_agent(
            CreateAgentCommand(external_id="agt_valid", currency="usd")  # Lowercase forbidden
        )

    # Non-positive rate limit
    with pytest.raises(ValueError, match="rate_limit_max"):
        await agent_lifecycle.create_agent(
            CreateAgentCommand(external_id="agt_valid", rate_limit_max=0)
        )

    # Non-positive daily quota
    with pytest.raises(ValueError, match="daily_quota_max"):
        await agent_lifecycle.create_agent(
            CreateAgentCommand(external_id="agt_valid", daily_quota_max=-10)
        )


async def test_no_plaintext_in_database(
    db_pool: asyncpg.Pool,
    agent_lifecycle: AgentLifecycle,
    delete_agent_cascade: Any,
) -> None:
    """Verify stored secret in PostgreSQL matches base64 CHECK and contains no plaintext."""
    ext_id = f"agt_{uuid.uuid4().hex[:12]}"
    created = await agent_lifecycle.create_agent(CreateAgentCommand(external_id=ext_id))
    try:
        async with db_pool.acquire() as conn:
            stored = await conn.fetchval(
                "SELECT secret_encrypted FROM agents WHERE id = $1;", created.agent_id
            )
        assert stored is not None
        assert stored != created.secret
        # Base64 envelope constraint holds
        assert re.fullmatch(r"^[A-Za-z0-9+/=]+$", stored)
    finally:
        await delete_agent_cascade(created.agent_id)


# -----------------------------------------------------------------------------
# 2. MERCHANT PROVISIONING & LIFECYCLE TESTS
# -----------------------------------------------------------------------------


async def test_create_merchant_happy_path(
    db_pool: asyncpg.Pool,
    merchant_lifecycle: MerchantLifecycle,
    merchant_repo: MerchantRepo,
    delete_merchant_cascade: Any,
) -> None:
    """Merchant provisioning creates merchants and ledger_accounts rows atomically."""
    ext_id = f"mch_{uuid.uuid4().hex[:12]}"
    cmd = CreateMerchantCommand(
        external_id=ext_id,
        name="Coffee Roasters LLC",
        currency="USDC",
    )

    created = await merchant_lifecycle.create_merchant(cmd)
    try:
        assert isinstance(created.merchant_id, uuid.UUID)
        assert created.external_id == ext_id
        # Merchants hold NO secret in Phase 1
        assert not hasattr(created, "secret")

        # Authoritative PostgreSQL verification
        async with db_pool.acquire() as conn:
            mch_row = await conn.fetchrow(
                "SELECT * FROM merchants WHERE id = $1;", created.merchant_id
            )
            assert mch_row is not None
            assert mch_row["external_id"] == ext_id
            assert mch_row["name"] == "Coffee Roasters LLC"
            assert mch_row["active"] is True
            assert mch_row["version"] == 1

            acct_row = await conn.fetchrow(
                "SELECT * FROM ledger_accounts WHERE owner_type = 'merchant' AND owner_id = $1;",
                created.merchant_id,
            )
            assert acct_row is not None
            assert acct_row["currency"] == "USDC"
            assert acct_row["balance"] == 0
            assert acct_row["version"] == 0

        # Read-through cache resolution immediately fresh post-commit
        resolved = await merchant_repo.resolve(ext_id)
        assert resolved is not None
        assert resolved.id == created.merchant_id
        assert resolved.external_id == ext_id
        assert resolved.active is True
    finally:
        await delete_merchant_cascade(created.merchant_id)


async def test_create_merchant_duplicate_raises(
    merchant_lifecycle: MerchantLifecycle,
    delete_merchant_cascade: Any,
) -> None:
    """Duplicate merchant external_id raises ValueError."""
    ext_id = f"mch_{uuid.uuid4().hex[:12]}"
    created = await merchant_lifecycle.create_merchant(CreateMerchantCommand(external_id=ext_id))
    try:
        with pytest.raises(ValueError, match="external_id already registered"):
            await merchant_lifecycle.create_merchant(CreateMerchantCommand(external_id=ext_id))
    finally:
        await delete_merchant_cascade(created.merchant_id)


async def test_suspend_merchant_and_activate_agent(
    agent_lifecycle: AgentLifecycle,
    agent_repo: AgentRepo,
    merchant_lifecycle: MerchantLifecycle,
    merchant_repo: MerchantRepo,
    delete_agent_cascade: Any,
    delete_merchant_cascade: Any,
) -> None:
    """Verify suspend_merchant and activate_agent properly update DB and invalidate caches."""
    # Merchant suspend flow
    mch_ext_id = f"mch_{uuid.uuid4().hex[:12]}"
    created_mch = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=mch_ext_id)
    )
    try:
        # Populate cache
        fresh_mch = await merchant_repo.resolve(mch_ext_id)
        assert fresh_mch is not None and fresh_mch.active is True

        # Suspend merchant
        suspended = await merchant_lifecycle.suspend_merchant(mch_ext_id)
        assert suspended is True

        # Idempotent second suspend returns False
        assert await merchant_lifecycle.suspend_merchant(mch_ext_id) is False

        # Read through returns active=False (MerchantRepo reports truth)
        after_suspend = await merchant_repo.resolve(mch_ext_id)
        assert after_suspend is not None
        assert after_suspend.active is False

        # Activate merchant back
        activated_mch = await merchant_lifecycle.activate_merchant(mch_ext_id)
        assert activated_mch is True
        reactivated = await merchant_repo.resolve(mch_ext_id)
        assert reactivated is not None and reactivated.active is True
    finally:
        await delete_merchant_cascade(created_mch.merchant_id)

    # Agent suspend & activate flow
    agt_ext_id = f"agt_{uuid.uuid4().hex[:12]}"
    created_agt = await agent_lifecycle.create_agent(CreateAgentCommand(external_id=agt_ext_id))
    try:
        # Suspend agent via lifecycle delegate
        suspended_agt = await agent_lifecycle.suspend_agent(created_agt.agent_id)
        assert suspended_agt is True

        # AgentRepo filters out inactive agents -> None
        assert await agent_repo.resolve(created_agt.agent_id) is None

        # Activate agent via lifecycle
        activated_agt = await agent_lifecycle.activate_agent(created_agt.agent_id)
        assert activated_agt is True

        # Idempotent activate returns False
        assert await agent_lifecycle.activate_agent(created_agt.agent_id) is False

        # AgentRepo resolves successfully after activation (Task 27 append invalidate proven)
        resolved_agt = await agent_repo.resolve(created_agt.agent_id)
        assert resolved_agt is not None
        assert resolved_agt.agent_id == created_agt.agent_id
    finally:
        await delete_agent_cascade(created_agt.agent_id)


# -----------------------------------------------------------------------------
# 3. BOOTSTRAP SEED & DETERMINISM TESTS
# -----------------------------------------------------------------------------


async def test_bootstrap_idempotency_and_uuid5_determinism(
    db_pool: asyncpg.Pool,
    bootstrap_seed_sql: str,
    apply_bootstrap: None,
) -> None:
    """Bootstrap creates system, fees, and treasury accounts with deterministic UUIDv5 owner IDs.

    Re-running bootstrap.sql is strictly idempotent and does not alter row counts.
    """
    # Recompute deterministic owner IDs in test (proven, not assumed)
    expected_system_id = uuid.uuid5(FLXPAY_NAMESPACE_UUID, "system")
    expected_fees_id = uuid.uuid5(FLXPAY_NAMESPACE_UUID, "fees")
    expected_treasury_id = uuid.uuid5(FLXPAY_NAMESPACE_UUID, "treasury")

    assert expected_system_id == SYSTEM_OWNER_ID
    assert expected_fees_id == FEES_OWNER_ID
    assert expected_treasury_id == TREASURY_OWNER_ID

    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT owner_type, owner_id, currency, balance, version
            FROM ledger_accounts
            WHERE owner_id = ANY($1::uuid[])
            ORDER BY owner_type;
            """,
            [expected_system_id, expected_fees_id, expected_treasury_id],
        )
        assert len(rows) == 3
        by_type = {r["owner_type"]: r for r in rows}

        assert by_type["system"]["owner_id"] == expected_system_id
        assert by_type["system"]["currency"] == "USDC"
        assert by_type["system"]["balance"] == 0

        assert by_type["fees"]["owner_id"] == expected_fees_id
        assert by_type["fees"]["currency"] == "USDC"
        assert by_type["fees"]["balance"] == 0

        assert by_type["treasury"]["owner_id"] == expected_treasury_id
        assert by_type["treasury"]["currency"] == "USDC"
        assert by_type["treasury"]["balance"] == 0

        # Re-run bootstrap seed to prove idempotency
        await conn.execute(bootstrap_seed_sql)

        count_after = await conn.fetchval(
            "SELECT count(*) FROM ledger_accounts WHERE owner_id = ANY($1::uuid[]);",
            [expected_system_id, expected_fees_id, expected_treasury_id],
        )
        assert count_after == 3


# -----------------------------------------------------------------------------
# 4. ACCOUNT DIRECTORY RESOLVER & CACHE TESTS
# -----------------------------------------------------------------------------


async def test_account_directory_lookups_and_cache(
    db_pool: asyncpg.Pool,
    account_directory: AccountDirectory,
    agent_lifecycle: AgentLifecycle,
    merchant_lifecycle: MerchantLifecycle,
    delete_agent_cascade: Any,
    delete_merchant_cascade: Any,
) -> None:
    """AccountDirectory resolves agent, merchant, and bootstrap platform accounts.

    Verifies in-process caching for fees/system/treasury and LookupError on missing accounts.
    """
    # 1. Platform accounts resolution
    reset_fees_cache()
    fees_ref = await account_directory.get_fees_account()
    assert fees_ref.owner_type == "fees"
    assert fees_ref.owner_id == FEES_OWNER_ID
    assert fees_ref.currency == "USDC"

    system_ref = await account_directory.get_system_account()
    assert system_ref.owner_type == "system"
    assert system_ref.owner_id == SYSTEM_OWNER_ID

    treasury_ref = await account_directory.get_treasury_account()
    assert treasury_ref.owner_type == "treasury"
    assert treasury_ref.owner_id == TREASURY_OWNER_ID

    # 2. In-process cache test: verify second call within TTL hits cache (no DB query)
    class ConnProxy:
        def __init__(self, conn: Any, on_fetchrow: Any) -> None:
            self._conn = conn
            self._on_fetchrow = on_fetchrow

        async def fetchrow(self, *args: Any, **kwargs: Any) -> Any:
            self._on_fetchrow()
            return await self._conn.fetchrow(*args, **kwargs)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._conn, name)

    class PoolSpy:
        def __init__(self, real_pool: asyncpg.Pool) -> None:
            self._real_pool = real_pool
            self.fetchrow_calls = 0

        def acquire(self) -> Any:
            real_ctx = self._real_pool.acquire()
            spy = self

            class ConnCtx:
                def __init__(self) -> None:
                    self._conn: Any = None

                async def __aenter__(self) -> Any:
                    self._conn = await real_ctx.__aenter__()

                    def _inc() -> None:
                        spy.fetchrow_calls += 1

                    return ConnProxy(self._conn, _inc)

                async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
                    await real_ctx.__aexit__(exc_type, exc_val, exc_tb)

            return ConnCtx()

    spy_pool = PoolSpy(db_pool)
    spy_directory = AccountDirectory(spy_pool)

    # First call: misses cache -> DB query count becomes 1
    reset_fees_cache()
    fees_first = await spy_directory.get_fees_account()
    assert fees_first.account_id == fees_ref.account_id
    assert spy_pool.fetchrow_calls == 1

    # Second call within TTL: served from in-process cache, fetchrow_calls remains 1
    fees_second = await spy_directory.get_fees_account()
    assert fees_second.account_id == fees_ref.account_id
    assert spy_pool.fetchrow_calls == 1

    # Reset cache hook: next call MUST query DB again -> fetchrow_calls becomes 2
    reset_fees_cache()
    fees_third = await spy_directory.get_fees_account()
    assert fees_third.account_id == fees_ref.account_id
    assert spy_pool.fetchrow_calls == 2

    # 3. Known agent account lookup
    agt_ext_id = f"agt_{uuid.uuid4().hex[:12]}"
    created_agt = await agent_lifecycle.create_agent(CreateAgentCommand(external_id=agt_ext_id))
    try:
        agt_ref = await account_directory.get_agent_account(created_agt.agent_id)
        assert agt_ref.owner_type == "agent"
        assert agt_ref.owner_id == created_agt.agent_id
        assert agt_ref.currency == "USDC"
    finally:
        await delete_agent_cascade(created_agt.agent_id)

    # 4. Unknown agent account lookup -> LookupError alarm
    fake_agt_id = uuid.uuid4()
    with pytest.raises(LookupError, match="Alarm-grade provisioning invariant broken"):
        await account_directory.get_agent_account(fake_agt_id)

    # 5. Known merchant account lookup
    mch_ext_id = f"mch_{uuid.uuid4().hex[:12]}"
    created_mch = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=mch_ext_id)
    )
    try:
        mch_ref = await account_directory.get_merchant_account(mch_ext_id)
        assert mch_ref.owner_type == "merchant"
        assert mch_ref.owner_id == created_mch.merchant_id
        assert mch_ref.currency == "USDC"
    finally:
        await delete_merchant_cascade(created_mch.merchant_id)

    # 6. Unknown merchant account lookup -> LookupError
    with pytest.raises(LookupError, match="Invariant broken"):
        await account_directory.get_merchant_account("mch_nonexistent_99")
