"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

from . import __version__
from .report import to_json, to_sarif, to_text
from .rules import RULES, SEVERITY_ORDER, SPECIAL_RULES
from .remote import RemoteError, fetch_github, is_remote
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
    p.add_argument("paths", nargs="*", help="skill folders, SKILL.md files, or GitHub URLs (scanned without cloning)")
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

    paths = list(args.paths)
    if len(paths) > 1 and paths[0] == "audit" and not os.path.exists("audit"):
        paths = paths[1:]  # `skillaudit audit <url>` is the same as `skillaudit <url>`

    missing = [p for p in paths if not is_remote(p) and not os.path.exists(p)]
    if missing:
        print(f"error: path not found: {', '.join(missing)}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="skillaudit-") as tmp:
        targets, labels = [], {}
        for i, p in enumerate(paths):
            if is_remote(p):
                print(f"Downloading {p} ...", file=sys.stderr)
                try:
                    fetched = fetch_github(p, Path(tmp) / f"repo{i}")
                except RemoteError as e:
                    print(f"error: {e}", file=sys.stderr)
                    return 2
                targets.append(str(fetched.path))
                labels[str(fetched.path)] = fetched.label
            else:
                targets.append(p)

        reports = scan_paths(targets, args.min_severity)
        for r in reports:
            for local, label in labels.items():
                if r.path == local or r.path.startswith(local + os.sep):
                    r.path = label + r.path[len(local):].replace(os.sep, "/")

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
