"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .report import to_json, to_sarif, to_text
from .rules import RULES, SEVERITY_ORDER, SPECIAL_RULES
from .scanner import scan_paths

BANNER = r"""
    _   _ _ _              _ _ _
 __| |_(_) | |__ _ _  _ __| (_) |_
(_-< / / | | / _` | || / _` | |  _|
/__/_\_\_|_|_\__,_|\_,_\__,_|_|\__|
"""


def _print_banner() -> None:
    red, dim, end = "\033[1;31m", "\033[2m", "\033[0m"
    print(f"{red}{BANNER}{end}{dim}  npm audit for AI agent skills  v{__version__}{end}\n")


def _list_rules() -> int:
    rows = [(r.id, r.severity, r.category, r.title) for r in RULES]
    rows += [(rid, sev, cat, title) for rid, title, sev, cat in SPECIAL_RULES]
    for rid, sev, cat, title in sorted(rows):
        print(f"{rid}  {sev:<8} {cat:<12} {title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="skillaudit",
        description="Security audit for AI agent skills (SKILL.md). Like `npm audit`, for skills.",
    )
    p.add_argument("paths", nargs="*", help="skill directories, SKILL.md files, or folders of skills")
    p.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="high",
                   help="exit with code 1 if a finding at or above this severity exists (default: high)")
    p.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low",
                   help="hide findings below this severity")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--no-banner", action="store_true", help="do not print the ASCII banner")
    p.add_argument("--list-rules", action="store_true", help="show all rules and exit")
    p.add_argument("--version", action="version", version=f"skillaudit {__version__}")
    return p


def _run(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        return _list_rules()
    if not args.paths:
        print("error: give at least one path, e.g. `skillaudit ~/.claude/skills`", file=sys.stderr)
        return 2

    missing = [p for p in args.paths if not os.path.exists(p)]
    if missing:
        print(f"error: path not found: {', '.join(missing)}", file=sys.stderr)
        return 2

    reports = scan_paths(args.paths, args.min_severity)
    if not reports:
        print("No skills found (looked for SKILL.md).", file=sys.stderr)
        return 2

    if args.format == "json":
        print(to_json(reports))
    elif args.format == "sarif":
        print(to_sarif(reports))
    else:
        color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
        if color and not args.no_banner:
            _print_banner()
        print(to_text(reports, color))

    floor = SEVERITY_ORDER[args.fail_on]
    failed = any(SEVERITY_ORDER[f.severity] >= floor for r in reports for f in r.findings)
    return 1 if failed else 0


def main(argv=None) -> int:
    try:
        return _run(argv)
    except BrokenPipeError:  # e.g. `skillaudit . | head`
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0
