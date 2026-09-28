"""FluxPay Gateway Subsystem.

Gateway Pipeline Architecture Map:
    canonical.py (Task 19: frozen signing scheme)
    -> ratelimit.lua (Task 20: atomic rate-limit and replay gate)
    -> middleware.py (Task 21: HTTP pipeline and request lifecycle)

Leaf-first imports:
    Lower-level pure cryptographic leaves (canonical.py) have zero project
    dependencies and are imported first by higher-level pipeline middleware.
"""
