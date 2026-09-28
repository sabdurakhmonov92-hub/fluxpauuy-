"""FluxPay Operator Dashboard Foundation (Block L - Task 61/62).

=============================================================================
THE THREE ARCHITECTURAL LAWS OF THE FLUXPAY DASHBOARD
=============================================================================

1. THE THIN-SHELL DOCTRINE:
   The dashboard is a THIN SHELL over the frozen domain and admin API.
   Every mutation passes through the existing audited endpoints (Task 29's admin
   router, Task 42's hold voting endpoint). The dashboard invents ZERO business
   logic, performs NO independent mutations of financial records, and enforces
   the exact same authorization rules as the underlying API. Views serve pages;
   repositories serve domain boundaries; the double-entry ledger remains the
   immutable truth of money.

2. THE SERVER-RENDERED MONOLITH DOCTRINE:
   Server-rendered HTML via Jinja2 + vendored htmx + ONE static CSS file.
   Zero node toolchain, zero bundler, zero npm dependencies, and zero client-side
   build steps. The dashboard is HTML shipped by the same Python monolith,
   hardened by the same typing and linting discipline.

3. THE ADMIN-PHASE-1 HONESTY DOCTRINE:
   This is the ADMIN dashboard in Phase 1 (agent owners ARE the platform admins
   at the 0-100 agent scale; Task 29 provisioned all required capabilities).
   Merchant self-service portals and granular merchant user hierarchies are
   deferred to Phase 2, documented honestly rather than hacked around with
   leaky abstractions.

=============================================================================
THE TECH-CHOICE ESSAY: WHY NOT AN SPA (THE FOUR SCARS)
=============================================================================

Senior engineers carry scar tissue from building payment dashboards with
single-page application (SPA) frameworks:

1. THE NODE TOOLCHAIN SCAR:
   A React/Vue SPA requires Node.js, npm/pnpm, and a bundler (Vite/Webpack) inside
   production systemd boxes and Dockerfiles. Toolchain incompatibilities, Node
   version mismatches, and build-time memory spikes regularly break production
   releases for what is fundamentally an internal operations portal.

2. THE SUPPLY-CHAIN AUDIT SCAR:
   A modern node_modules directory contains thousands of transitive packages.
   A single high-severity CVE in a deeply nested transitive dependency blocks CI/CD
   pipelines, requiring emergency dependency surgery for code that has nothing to do
   with moving money. Vendoring htmx (a single audited 14KB file) eliminates the entire
   supply-chain attack vector.

3. THE BUNDLE BLOAT SCAR:
   Shipping a 4MB JavaScript bundle containing multiple component libraries, router
   runtimes, and virtual DOM diffing logic for three operator screens (balances,
   API keys, limits) degrades page loads and consumes unnecessary client memory.
   Fast HTML responses rendered in under 5ms from Python memory provide a faster,
   crisper operator experience.

4. THE LOCALSTORAGE XSS SCAR:
   SPAs typically store OAuth access/refresh tokens in localStorage or sessionStorage
   so client JavaScript can attach Bearer headers. Any minor XSS vulnerability
   (e.g., in an untrusted agent description or third-party script) results in instant,
   silent exfiltration of long-lived credentials. By contrast, FluxPay's session
   lives in an HttpOnly, Secure, SameSite=Strict cookie with an 8-hour ceiling,
   completely inaccessible to JavaScript.

=============================================================================
LANE MAP & THE NEVER-MERGE DOCTRINE
=============================================================================

FluxPay enforces three strictly isolated HTTP execution lanes:

  1. GATEWAY LANE (/v1/*):
     Authenticated via HMAC-SHA256 signatures, anti-replay nonces, and timestamp
     windows (GatewayMiddleware). Consumed by autonomous machine agents.

  2. ADMIN API LANE (/admin/*):
     Authenticated via Keycloak Bearer JWTs and PostgreSQL user row verification
     (AdminAuthMiddleware). Consumed by machine CLI tools, automation scripts, and
     headless administrative agents.

  3. DASHBOARD LANE (/dashboard/*):
     Authenticated via signed, encrypted HttpOnly session cookies (DashboardAuthMiddleware).
     Protected by three-layer CSRF defense (SameSite=Strict, Origin matching, and
     mandatory HX-Request headers). Consumed by human browser operators.

These three lanes NEVER merge. Their credentials, error representations, and auth
mechanisms remain orthogonal and unentangled.
"""

from __future__ import annotations

__all__ = [
    "DASHBOARD_PREFIX",
]

DASHBOARD_PREFIX: str = "/dashboard"
