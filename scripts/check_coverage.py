"""Per-module test coverage gate enforcement script.

WHY a script not pytest-cov fail_under:
coverage.py's fail_under option is GLOBAL only across the entire repository.
Per-module quality gates (e.g. demanding >= 95% on the Block C money core while
other modules undergo development) require isolated prefix filtering.
Gateway (Task 25) and payments (Task 33) will add their own module-specific
gates with this same script — one mechanism, many gates.

Exit codes:
0 = Pass (coverage >= threshold)
1 = Fail (coverage < threshold)
2 = Operational error (missing file, malformed JSON, invalid arguments)
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Final

EXIT_PASS: Final[int] = 0
EXIT_FAIL: Final[int] = 1
EXIT_OPS_ERROR: Final[int] = 2


def _matches_prefix(file_path: str, prefix: str) -> bool:
    """Check if normalized file_path falls under normalized prefix."""
    norm_path = file_path.replace("\\", "/").strip("./")
    norm_prefix = prefix.replace("\\", "/").strip("./")
    return (
        norm_path == norm_prefix
        or norm_path.startswith(f"{norm_prefix}/")
        or f"/{norm_prefix}/" in f"/{norm_path}"
    )


def check_coverage(prefix: str, threshold: float, file_path: Path) -> int:
    """Parse coverage.json and enforce the threshold for files matching prefix."""
    if not file_path.is_file():
        sys.stderr.write(f"Operational error: coverage file '{file_path}' not found.\n")
        return EXIT_OPS_ERROR

    try:
        content = file_path.read_text(encoding="utf-8")
        data: dict[str, Any] = json.loads(content)
    except Exception as exc:
        sys.stderr.write(f"Operational error: malformed JSON in '{file_path}': {exc}\n")
        return EXIT_OPS_ERROR

    if not isinstance(data, dict) or "files" not in data or not isinstance(data["files"], dict):
        sys.stderr.write("Operational error: malformed coverage.json missing 'files' dictionary.\n")
        return EXIT_OPS_ERROR

    files: dict[str, Any] = data["files"]
    total_covered = 0
    total_statements = 0
    matched_files = 0

    for path, meta in files.items():
        if not _matches_prefix(path, prefix):
            continue

        matched_files += 1
        summary = meta.get("summary")
        if not isinstance(summary, dict):
            sys.stderr.write(f"Operational error: missing summary dict for '{path}'.\n")
            return EXIT_OPS_ERROR

        if "covered_lines" not in summary or "num_statements" not in summary:
            sys.stderr.write(
                f"Operational error: missing statement counts in summary for '{path}'.\n"
            )
            return EXIT_OPS_ERROR

        covered = summary["covered_lines"]
        statements = summary["num_statements"]

        if not isinstance(covered, (int, float)) or not isinstance(statements, (int, float)):
            sys.stderr.write(f"Operational error: non-numeric statement counts for '{path}'.\n")
            return EXIT_OPS_ERROR

        total_covered += int(covered)
        total_statements += int(statements)

    if total_statements == 0:
        pct = 0.0
    else:
        pct = (total_covered / total_statements) * 100.0

    threshold_formatted = f"{threshold:.2f}" if threshold != int(threshold) else f"{int(threshold)}"

    if pct >= threshold and matched_files > 0:
        print(f"GATE {prefix} {pct:.2f}% >= {threshold_formatted}% -> PASS")
        return EXIT_PASS
    else:
        print(f"GATE {prefix} {pct:.2f}% >= {threshold_formatted}% -> FAIL")
        return EXIT_FAIL


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Enforce per-module test coverage threshold from coverage.json."
    )
    parser.add_argument(
        "prefix",
        help="Path prefix to filter files (e.g. src/fluxpay/ledger)",
    )
    parser.add_argument(
        "threshold",
        type=float,
        help="Coverage percentage threshold between 0 and 100",
    )
    parser.add_argument(
        "--file",
        "-f",
        default="coverage.json",
        help="Path to coverage.json file (default: coverage.json)",
    )

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_OPS_ERROR

    if args.threshold < 0.0 or args.threshold > 100.0:
        sys.stderr.write(
            f"Operational error: threshold must be in range [0, 100], got {args.threshold}\n"
        )
        return EXIT_OPS_ERROR

    return check_coverage(args.prefix, args.threshold, Path(args.file))


if __name__ == "__main__":
    sys.exit(main())
