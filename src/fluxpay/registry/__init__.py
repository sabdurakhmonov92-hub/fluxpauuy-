"""FluxPay Registry Subsystem.

Registry Architectural Map:
    repo.py (Task 23: auth-path reads + suspend)
    -> agents.py (Task 27: agent lifecycle, atomic agent + ledger account creation)
    -> limits.py (Task 28: effective limits and velocity controls)

Dependency Direction Law:
    Registry imports shared/, never gateway internals.
    The gateway imports registry interfaces via the AgentResolver Protocol seam.
"""
