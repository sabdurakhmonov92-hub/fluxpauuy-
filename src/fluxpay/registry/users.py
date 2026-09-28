"""Admin and dashboard user repository for FluxPay.

Blueprint §7 Admin Plane & RBAC Anchor.

=============================================================================
SECURITY & REPOSITORY DESIGN DECISIONS (WHY THE SYSTEM IS BUILT THIS WAY)
=============================================================================

1. WHY KEYCLOAK_SUB IS TEXT, NOT UUID:
--------------------------------------
Keycloak subject identifiers are opaque strings assigned by the Identity Provider.
While default Keycloak realm configurations often emit UUID-shaped strings, Keycloak
allows external identity brokering (LDAP, SAML, Google, GitHub) where subjects can take
arbitrary string formats (e.g., email-like, base64-encoded, or numeric). Treating
`keycloak_sub` as a PostgreSQL UUID type would rigidly couple our database schema to
Keycloak's internal ID generator. `TEXT` guarantees protocol compatibility across all IdP
sources without schema migrations.

2. WHY DEFENSE-IN-DEPTH RBAC (Role-in-DB Anchor):
-------------------------------------------------
Keycloak is the Identity Provider and mints signed JWTs containing user claims and roles.
However, relying solely on stateless JWT verification creates a critical security gap:
revocation lag. If an admin or support operator is terminated, or their privileges are
revoked, their existing JWT remains valid until its expiry (often 5-15 minutes).
In FluxPay, Task 29's admin middleware enforces defense in depth:
Every authenticated admin request must verify both the Keycloak JWT AND this `users` table row.
If `active` is False or the user row is absent, the request is immediately rejected,
protecting against stale tokens even if the IdP was slow to revoke.

3. WHY NO CACHE FOR USERS:
--------------------------
Admin plane requests are infrequent (cold path) compared to the payment and agent auth paths.
Caching user records in Redis would introduce cache invalidation bugs and risk windowing
a revoked user's access. Sub-millisecond B-tree primary key and unique index lookups in
PostgreSQL provide all the throughput required for administrative workloads while ensuring
zero revocation lag (Task 23 cold-path philosophy).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]

__all__ = [
    "UserRecord",
    "UserRepo",
]


@dataclass(frozen=True, slots=True)
class UserRecord:
    """Read-only view of admin or support user record.

    Represents the internal RBAC anchor for dashboard operators.
    """

    id: UUID
    keycloak_sub: str
    email: str
    display_name: str
    role: str
    active: bool
    created_at: datetime | None = None


class UserRepo:
    """PostgreSQL repository for admin and support user records.

    Provides direct, authoritative lookups without caching.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def get_by_keycloak_sub(self, sub: str) -> UserRecord | None:
        """Fetch user record by Keycloak subject identifier.

        Returns UserRecord if present, or None if absent.
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, keycloak_sub, email, display_name, role, active, created_at
                FROM users
                WHERE keycloak_sub = $1;
                """,
                sub,
            )

        if row is None:
            return None

        return UserRecord(
            id=row["id"],
            keycloak_sub=row["keycloak_sub"],
            email=row["email"],
            display_name=row["display_name"],
            role=row["role"],
            active=row["active"],
            created_at=row["created_at"],
        )

    async def get(self, user_id: UUID) -> UserRecord | None:
        """Fetch user record by primary key UUID.

        Returns UserRecord if present, or None if absent.
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, keycloak_sub, email, display_name, role, active, created_at
                FROM users
                WHERE id = $1;
                """,
                user_id,
            )

        if row is None:
            return None

        return UserRecord(
            id=row["id"],
            keycloak_sub=row["keycloak_sub"],
            email=row["email"],
            display_name=row["display_name"],
            role=row["role"],
            active=row["active"],
            created_at=row["created_at"],
        )
