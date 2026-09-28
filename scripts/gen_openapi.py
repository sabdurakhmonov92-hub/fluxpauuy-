#!/usr/bin/env python3
"""OpenAPI Snapshot Generator.

Generates contracts/openapi.json snapshot directly from the FastAPI application.
Ensures zero runtime secret dependency for headless generation in CI and development.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# Provide synthetic configuration so create_app() can instantiate without live secrets/DB
os.environ.setdefault("FLX_PG_DSN", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("FLX_VAULT_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("FLX_WEBHOOK_SIGNING_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("FLX_ENV", "development")

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = REPO_ROOT / "contracts" / "openapi.json"


def generate_openapi() -> dict:
    """Generate OpenAPI schema dictionary from the FastAPI app."""
    from fluxpay.main import create_app

    app = create_app()
    return app.openapi()


def main() -> None:
    schema = generate_openapi()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)
        f.write("\n")
    print(f"Generated OpenAPI schema snapshot at: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
