"""Find skills and scan their files."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .rules import RULES, SEVERITY_ORDER, SEVERITY_WEIGHT

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache"}
MAX_BYTES = 1_000_000
HIDDEN_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
URL_HOST_RE = re.compile(r"https?://([A-Za-z0-9.-]+)")
SCRIPT_EXT = {".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".mjs", ".cjs", ".rb", ".pl", ".ps1", ".bat"}
IGNORE_RE = re.compile(r"skillaudit-ignore[:\s]+([A-Za-z0-9_, ]+)")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    file: str
    line: int
    snippet: str
    advice: str


@dataclass
class SkillReport:
    name: str
    path: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    scripts: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    allowed_tools: str = ""

    @property
    def score(self) -> int:
        """Risk score 0-100. Distinct rules count fully, repeats add a little."""
        seen = {}
        for f in self.findings:
            seen.setdefault(f.rule_id, []).append(f)
        total = 0
        for items in seen.values():
            total += SEVERITY_WEIGHT[items[0].severity] + 2 * (len(items) - 1)
        return min(100, total)

    @property
    def verdict(self) -> str:
        sevs = {f.severity for f in self.findings}
        if "critical" in sevs or self.score >= 70:
            return "DANGEROUS"
        if "high" in sevs or self.score >= 25:
            return "REVIEW"
        if self.findings:
            return "LOW RISK"
        return "CLEAN"


def parse_frontmatter(text: str) -> Optional[dict]:
    """Tiny YAML-subset parser (key: value). Returns None if no frontmatter."""
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    data = {}
    for line in text[3:end].splitlines():
        m = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", line)
        if m:
            data[m.group(1).lower()] = m.group(2).strip()
    return data


def find_skills(root: str) -> List[Path]:
    """Return directories that contain a SKILL.md (given a dir, or a SKILL.md file)."""
    p = Path(root)
    if p.is_file():
        return [p.parent] if p.name.lower() == "skill.md" else []
    skills = []
    for dirpath, dirnames, filenames in os.walk(p):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if any(f.lower() == "skill.md" for f in filenames):
            skills.append(Path(dirpath))
    return sorted(skills)


def _is_ignored(line: str, prev_line: str, rule_id: str) -> bool:
    for candidate in (line, prev_line):
        m = IGNORE_RE.search(candidate)
        if m:
            ids = {x.strip().upper() for x in m.group(1).split(",")}
            if rule_id in ids or "ALL" in ids:
                return True
    return False


def _scan_text(text: str, rel: str, out: List[Finding]) -> None:
    lines = text.splitlines()
    for i, line in enumerate(lines):
        prev = lines[i - 1] if i else ""
        for rule in RULES:
            if rule.pattern.search(line) and not _is_ignored(line, prev, rule.id):
                snippet = HIDDEN_RE.sub(lambda m: f"<U+{ord(m.group()):04X}>", line.strip())
                out.append(
                    Finding(rule.id, rule.title, rule.severity, rule.category,
                            rel, i + 1, snippet[:110], rule.advice)
                )


def scan_skill(skill_dir: Path, min_severity: str = "low") -> SkillReport:
    report = SkillReport(name=skill_dir.name, path=str(skill_dir))
    nested = {d for d in find_skills(str(skill_dir)) if d != skill_dir}

    for dirpath, dirnames, filenames in os.walk(skill_dir):
        here = Path(dirpath)
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and (here / d) not in nested]
        for fname in filenames:
            fpath = here / fname
            rel = fpath.relative_to(skill_dir).as_posix()  # same output on Windows and Linux

            if fpath.is_symlink():
                target = fpath.resolve()
                if skill_dir.resolve() not in target.parents and target != skill_dir.resolve():
                    report.findings.append(Finding(
                        "SA017", "Symlink pointing outside the skill directory", "high",
                        "execution", rel, 0, f"-> {os.readlink(fpath)}",
                        "A symlink can expose files outside the skill. Copy what you need instead."))
                continue
            try:
                if fpath.stat().st_size > MAX_BYTES:
                    continue
                raw = fpath.read_bytes()
            except OSError:
                continue

            if b"\0" in raw[:2048]:
                report.findings.append(Finding(
                    "SA016", "Opaque binary file that cannot be audited", "medium",
                    "execution", rel, 0, f"{len(raw)} bytes",
                    "Prefer readable scripts. Binaries inside skills cannot be reviewed."))
                continue

            text = raw.decode("utf-8", errors="replace")
            report.files_scanned += 1
            _scan_text(text, rel, report.findings)

            if fpath.suffix.lower() in SCRIPT_EXT:
                report.scripts.append(rel)
            for host in URL_HOST_RE.findall(text):
                host = host.strip(".").lower()
                if host and host not in report.hosts:
                    report.hosts.append(host)

            if fname.lower() == "skill.md":
                _check_skill_md(text, rel, report.findings)
                fm = parse_frontmatter(text) or {}
                report.allowed_tools = fm.get("allowed-tools", "")

    report.hosts.sort()
    report.scripts.sort()
    floor = SEVERITY_ORDER[min_severity]
    report.findings = [f for f in report.findings if SEVERITY_ORDER[f.severity] >= floor]
    report.findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line))
    return report


def _check_skill_md(text: str, rel: str, out: List[Finding]) -> None:
    fm = parse_frontmatter(text)
    if fm is None or not fm.get("description"):
        out.append(Finding(
            "SA015", "SKILL.md is missing frontmatter or a description", "low", "quality",
            rel, 1, "", "Add --- frontmatter with name and description."))
        return
    tools = fm.get("allowed-tools", "")
    tokens = re.findall(r"[A-Za-z_]+(?:\([^)]*\))?|\*", tools)
    if any(t in {"*", "Bash", "Bash(*)", "Bash(*:*)"} for t in tokens):
        out.append(Finding(
            "SA008", "Over-broad allowed-tools (unscoped Bash or wildcard)", "medium",
            "privilege", rel, 1, f"allowed-tools: {tools[:80]}",
            "Scope tools narrowly, e.g. Bash(git status:*), instead of granting everything."))


def scan_paths(paths: List[str], min_severity: str = "low") -> List[SkillReport]:
    reports = []
    for p in paths:
        for skill in find_skills(p):
            reports.append(scan_skill(skill, min_severity))
    return reports
