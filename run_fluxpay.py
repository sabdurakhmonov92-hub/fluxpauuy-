"""FluxPay Unified Production Application Runner (Part 1.3).

Single entrypoint executing the complete FluxPay financial operating system.
Provides CLI argument parsing, environment validation, database migration
execution, dependency injection initialization, and graceful Uvicorn process management.

Usage:
    python run_fluxpay.py [--env development|staging|production] [--host 0.0.0.0]
                          [--port 8000] [--workers 1] [--migrate] [--no-browser]
"""

from __future__ import annotations

import argparse
import contextlib
import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any

# Ensure project root and src/ are in sys.path
ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


def _load_env_file(env_name: str) -> None:
    """Load matching .env file if present, falling back to .env or .env.development."""
    env_file = ROOT_DIR / f".env.{env_name}"
    if not env_file.exists():
        env_file = ROOT_DIR / ".env"

    if env_file.exists():
        try:
            from dotenv import load_dotenv

            load_dotenv(dotenv_path=env_file, override=False)
        except ImportError:
            # Lightweight fallback dotenv parser if python-dotenv is not installed
            for line in env_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    v = v.strip().strip("'\"")
                    os.environ.setdefault(k.strip(), v)


def is_port_in_use(host: str, port: int) -> bool:
    """Check if a network socket is already bound."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def find_available_port(host: str, start_port: int = 8000) -> int:
    """Find first available network port starting from start_port."""
    port = start_port
    while port < start_port + 50:
        if not is_port_in_use(host, port):
            return port
        port += 1
    return start_port


def print_banner(host: str, port: int, env: str, workers: int) -> None:
    """Print high-visibility production terminal banner."""
    from fluxpay import __version__
    from fluxpay.config import get_settings

    settings = get_settings()
    url = f"http://{host}:{port}/"
    border = "=" * 76
    print(f"\n{border}")
    print(f"   [+] FLUXPAY v{__version__} -- AUTONOMOUS AI AGENT PAYMENT OPERATING SYSTEM")
    print(f"{border}")
    print(f"   [+] Environment:    {env.upper()}")
    print(f"   [+] Workers:        {workers}")
    print(f"   [+] Blockchain:     Base L2 (Chain ID: {settings.base_chain_id})")
    print(f"   [+] USDC Contract:  {settings.base_usdc_address}")
    print("   [+] Architecture:   Modular Monolith / Double-Entry Invariant Ledger")
    print(f"   [+] Gateway Ingress: {url}v1/payments")
    print(f"   [+] x402 Protocol:   {url}x402/challenge")
    print(f"   [+] Unified Console: {url}")
    print(f"   [+] Health & Ready:  {url}health  |  {url}ready")
    print(f"   [+] Metrics:         {url}metrics")
    print(f"{border}\n")


def open_browser_delayed(url: str, delay: float = 1.2) -> None:
    """Open default browser after server starts listening (development mode)."""

    def _open() -> None:
        time.sleep(delay)
        with contextlib.suppress(Exception):
            webbrowser.open(url)

    threading.Thread(target=_open, daemon=True).start()


def run_migrations_sync() -> None:
    """Run database schema migrations if requested."""
    import asyncio

    from scripts.migrate import run_migrations

    print("   [*] Executing database migrations...")
    asyncio.run(run_migrations(dry_run=False))
    print("   [+] Database migrations applied successfully.")


def parse_args() -> argparse.Namespace:
    """Parse command line flags."""
    parser = argparse.ArgumentParser(
        description="FluxPay Autonomous AI Agent Payment Infrastructure Runner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--env",
        choices=["development", "staging", "production"],
        default=os.environ.get("FLX_ENV", "development"),
        help="Target operational environment",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("FLX_HOST", "127.0.0.1"),
        help="Host address to bind the HTTP server",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("FLX_PORT", "8000")),
        help="Port number to bind the HTTP server",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=int(os.environ.get("FLX_WORKERS", "1")),
        help="Number of Uvicorn worker processes",
    )
    parser.add_argument(
        "--migrate",
        action="store_true",
        help="Run database schema migrations before starting the application",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Disable automatic browser opening in development mode",
    )
    return parser.parse_args()


def main() -> None:
    """Primary application runner entrypoint."""
    args = parse_args()

    # Step 1: Set environment and load appropriate .env
    os.environ["FLX_ENV"] = args.env
    _load_env_file(args.env)

    # Defaults for local development convenience if not explicitly set
    if args.env == "development":
        os.environ.setdefault("FLX_DASHBOARD_SECRET", "fluxpay-standalone-secret-key-32b-ok")
        os.environ.setdefault("FLX_DASHBOARD_ORIGIN", f"http://{args.host}:{args.port}")
        os.environ.setdefault(
            "FLX_VAULT_MASTER_KEY", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
        )
        os.environ.setdefault(
            "FLX_WEBHOOK_SIGNING_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )

    # Step 2: Validate all required environment variables (fail-fast)
    from fluxpay.config import get_settings

    try:
        settings = get_settings()
    except Exception as exc:
        sys.stderr.write(f"\n[FATAL] Configuration invariant validation failed:\n{exc}\n\n")
        sys.exit(1)

    # Step 3: Run migrations if requested
    if args.migrate:
        try:
            run_migrations_sync()
        except Exception as exc:
            sys.stderr.write(f"\n[FATAL] Migration execution failed:\n{exc}\n\n")
            sys.exit(1)

    # Step 4: Resolve port availability
    target_host = args.host
    target_port = args.port
    if args.env == "development" and is_port_in_use(target_host, target_port):
        target_port = find_available_port(target_host, target_port + 1)
        print(f"   [!] Port {args.port} in use; falling back to port {target_port}")

    # Step 5: Print Banner & Launch browser in dev
    print_banner(target_host, target_port, args.env, args.workers)
    if args.env == "development" and not args.no_browser:
        open_browser_delayed(f"http://{target_host}:{target_port}/")

    # Step 6: Start Uvicorn ASGI server with graceful shutdown
    import uvicorn

    uvicorn_kwargs: dict[str, Any] = {
        "host": target_host,
        "port": target_port,
        "log_level": settings.log_level.lower(),
        "timeout_graceful_shutdown": 30,
    }

    if args.workers > 1:
        uvicorn_kwargs["workers"] = args.workers
        uvicorn.run("fluxpay.main:create_app", factory=True, **uvicorn_kwargs)
    else:
        from fluxpay.main import create_app

        application = create_app()
        uvicorn.run(application, **uvicorn_kwargs)


if __name__ == "__main__":
    main()
