"""Compatibility entry point for FluxPay verify CLI.

Re-exports the core operational contract and entry points from
the fluxpay.ledger.verify package.
"""

import sys

from fluxpay.ledger.verify import (
    EXIT_CHAIN_BROKEN,
    EXIT_OK,
    EXIT_OPS_FAILURE,
    main,
    run_verification,
)

__all__ = [
    "EXIT_CHAIN_BROKEN",
    "EXIT_OK",
    "EXIT_OPS_FAILURE",
    "main",
    "run_verification",
]

if __name__ == "__main__":
    sys.exit(main())
