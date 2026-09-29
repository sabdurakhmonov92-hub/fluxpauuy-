"""FluxPay All-in-One Single-Page Application Runner.

Executes the complete FluxPay financial operating system and launches the
unified single-page console in the default web browser.

Usage:
    python run_fluxpay.py
    # or
    uv run python run_fluxpay.py
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

# Ensure project root and src/ are in sys.path
ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"
TESTS_DIR = ROOT_DIR / "tests"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Default environment configuration for standalone runner
os.environ.setdefault("FLX_ENV", "development")
os.environ.setdefault("FLX_DASHBOARD_SECRET", "fluxpay-standalone-secret-key-32b-ok")
os.environ.setdefault("FLX_DASHBOARD_ORIGIN", "http://localhost:8000")
os.environ.setdefault("FLX_VAULT_MASTER_KEY", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
os.environ.setdefault("FLX_WEBHOOK_SIGNING_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")


if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def is_port_in_use(port: int) -> bool:
    """Check if a network port is already bound."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def find_available_port(start_port: int = 8000) -> int:
    """Find first open port starting from start_port."""
    port = start_port
    while port < start_port + 50:
        if not is_port_in_use(port):
            return port
        port += 1
    return start_port


def print_banner(host: str, port: int) -> None:
    """Print high-visibility terminal banner."""
    url = f"http://{host}:{port}/"
    border = "=" * 74
    print(f"\n{border}")
    print("   [+] FLUXPAY v3 -- AUTONOMOUS AI AGENT PAYMENT OPERATING SYSTEM")
    print(f"{border}")
    print("   [+] Architecture: Double-Entry Cryptographic Invariant Ledger")
    print("   [+] Integrity:    SHA-256 Hashchain & Tamper-Evident Blocks")
    print("   [+] Console Mode: Unified All-in-One Single Page Interface")
    print(f"   [+] Access URL:   {url}")
    print(f"{border}\n")


def open_browser_delayed(url: str, delay: float = 1.2) -> None:
    """Open default browser after server starts listening."""
    def _open():
        time.sleep(delay)
        try:
            webbrowser.open(url)
        except Exception:
            pass
    threading.Thread(target=_open, daemon=True).start()


def main() -> None:
    """Launch the unified FluxPay web service."""
    import uvicorn
    from fastapi import FastAPI
    from starlette.staticfiles import StaticFiles

    from fluxpay.config import get_settings
    from fluxpay.console.router import router as console_router

    # Build FastAPI application
    app = FastAPI(
        title="FluxPay Unified Console",
        version="3.0.0",
        description="Autonomous AI Agent Financial Infrastructure & Double-Entry Ledger",
    )

    # Mount static files
    static_dir = ROOT_DIR / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Mount the unified single-page console router
    app.include_router(console_router)

    # Health probe
    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "mode": "unified_console", "version": "3.0.0"}

    # Resolve port
    host = "127.0.0.1"
    port = 8000
    if is_port_in_use(port):
        port = find_available_port(8001)

    url = f"http://{host}:{port}/"
    print_banner(host, port)
    open_browser_delayed(url)

    # Run Uvicorn server
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
