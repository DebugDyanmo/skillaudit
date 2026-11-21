"""Output formats: text, json, sarif."""

from __future__ import annotations

import json
from typing import List

from . import __version__
from .rules import RULES, SPECIAL_RULES
from .scanner import SkillReport

COLORS = {
    "critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m",
    "CLEAN": "\033[32m", "LOW RISK": "\033[36m", "REVIEW": "\033[33m", "DANGEROUS": "\033[1;31m",
    "dim": "\033[2m", "bold": "\033[1m", "end": "\033[0m",
}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _c(text: str, key: str, color: bool) -> str:
    return f"{COLORS[key]}{text}{COLORS['end']}" if color else text


def to_text(reports: List[SkillReport], color: bool = True) -> str:
    out = []
    for r in reports:
        head = f"{r.name}  [{_c(r.verdict, r.verdict, color)}]  risk {r.score}/100"
        out.append(_c(head, "bold", color))
        out.append(_c(f"  {r.path}  ({r.files_scanned} files scanned)", "dim", color))
        if not r.findings:
            out.append("  No known risky patterns found. This is not a guarantee of safety.")
        for f in r.findings:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            out.append(f"  {_c(f.severity.upper().ljust(8), f.severity, color)} {f.rule_id}  {f.title}")
            out.append(_c(f"           {loc}", "dim", color))
            if f.snippet:
                out.append(f"           > {f.snippet}")
            out.append(f"           fix: {f.advice}")
        out.append(_c("  Capabilities (what this skill can do):", "bold", color))
        out.append(f"    scripts : {', '.join(r.scripts) if r.scripts else 'none bundled'}")
        hosts = ", ".join(r.hosts[:6]) + (" ..." if len(r.hosts) > 6 else "")
        out.append(f"    network : {hosts if r.hosts else 'no external hosts referenced'}")
        out.append(f"    tools   : {r.allowed_tools if r.allowed_tools else 'not declared'}")
        out.append("")
    total = sum(len(r.findings) for r in reports)
    out.append(f"Scanned {len(reports)} skill(s), {total} finding(s).")
    return "\n".join(out)


def to_json(reports: List[SkillReport]) -> str:
    return json.dumps(
        {
            "tool": "skillaudit", "version": __version__,
            "skills": [
                {
                    "name": r.name, "path": r.path, "verdict": r.verdict, "score": r.score,
                    "files_scanned": r.files_scanned,
                    "capabilities": {"scripts": r.scripts, "hosts": r.hosts,
                                     "allowed_tools": r.allowed_tools},
                    "findings": [f.__dict__ for f in r.findings],
                }
                for r in reports
            ],
        },
        indent=2,
    )


def to_sarif(reports: List[SkillReport]) -> str:
    rules = [
        {"id": r.id, "name": r.title, "shortDescription": {"text": r.title},
         "properties": {"category": r.category}}
        for r in RULES
    ] + [
        {"id": rid, "name": title, "shortDescription": {"text": title},
         "properties": {"category": cat}}
        for rid, title, _sev, cat in SPECIAL_RULES
    ]
    results = []
    for rep in reports:
        for f in rep.findings:
            results.append({
                "ruleId": f.rule_id,
                "level": SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title}. {f.advice}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"{rep.path}/{f.file}".replace("\\", "/")},
                        "region": {"startLine": max(f.line, 1)},
                    }
                }],
            })
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "skillaudit", "version": __version__,
                                "informationUri": "https://github.com/YOUR-USERNAME/skillaudit",
                                "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
