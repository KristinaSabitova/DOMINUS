#!/usr/bin/env python3
"""DOMINUS — CLI entry point for OSINT domain/company reconnaissance."""
from __future__ import annotations

import argparse
import sys

from dominus import __version__
from dominus.core.engine import PHASES, Engine

PHASE_CHOICES = list(PHASES.keys())


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="dominus",
        description="OSINT reconnaissance for domains and companies.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=f"Available phases: {', '.join(PHASE_CHOICES)}",
    )
    parser.add_argument("target", help="Target domain (e.g. example.com)")
    parser.add_argument(
        "-o", "--output",
        default="output",
        help="Output directory for reports",
    )

    selection = parser.add_mutually_exclusive_group()
    selection.add_argument(
        "--skip",
        nargs="+",
        default=[],
        choices=PHASE_CHOICES,
        metavar="PHASE",
        help="Phases to skip",
    )
    selection.add_argument(
        "--only",
        nargs="+",
        default=[],
        choices=PHASE_CHOICES,
        metavar="PHASE",
        help="Run only these phases",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Also write a JSON report alongside the HTML",
    )
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Skip HTML report generation (use with --json)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose logging",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"DOMINUS {__version__}",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.no_html and not args.json:
        print(
            "error: --no-html requires --json (no output would be produced)",
            file=sys.stderr,
        )
        return 2

    engine = Engine(
        target=args.target,
        output_dir=args.output,
        skip=args.skip,
        only=args.only,
        verbose=args.verbose,
        write_html=not args.no_html,
        write_json=args.json,
    )

    try:
        engine.run()
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"fatal: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
