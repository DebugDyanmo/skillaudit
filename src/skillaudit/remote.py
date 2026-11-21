"""Fetch a GitHub repository as a zip and unpack it safely.

Nothing from the downloaded repository is ever executed. The archive is read
into memory with size limits, extracted into a temporary folder, scanned, and
deleted by the caller.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import stat
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import quote, unquote, urlparse

MAX_DOWNLOAD = 50 * 1024 * 1024    # 50 MB compressed
MAX_UNPACKED = 200 * 1024 * 1024   # 200 MB uncompressed
MAX_FILES = 20_000
TIMEOUT = 30
USER_AGENT = "skillaudit (+https://github.com/DebugDyanmo/skillaudit)"

_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_REF = re.compile(r"^[A-Za-z0-9_./-]+$")


class RemoteError(Exception):
    """A problem fetching or unpacking a remote repository."""


@dataclass(frozen=True)
class GitHubRef:
    owner: str
    repo: str
    ref: Optional[str]
    subpath: str

    @property
    def label(self) -> str:
        out = f"github.com/{self.owner}/{self.repo}"
        if self.ref:
            out += f"@{self.ref}"
        if self.subpath:
            out += f"/{self.subpath}"
        return out


@dataclass(frozen=True)
class Fetched:
    path: Path
    label: str


def is_remote(arg: str) -> bool:
    a = arg.strip().lower()
    return a.startswith(("https://github.com/", "http://github.com/",
                         "https://www.github.com/", "github:"))


def parse_github(arg: str) -> GitHubRef:
    a = arg.strip()
    if a.lower().startswith("github:"):
        a = "https://github.com/" + a[7:].lstrip("/")
    u = urlparse(a)
    if u.scheme not in ("http", "https") or u.netloc.lower() not in ("github.com", "www.github.com"):
        raise RemoteError("Only github.com URLs are supported.")
    parts = [unquote(p) for p in u.path.split("/") if p]
    if len(parts) < 2:
        raise RemoteError("Expected a URL like https://github.com/<owner>/<repo>")
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not _NAME.match(owner) or not _NAME.match(repo):
        raise RemoteError("Invalid owner or repository name.")

    ref, sub = None, ""
    if len(parts) > 2:
        if parts[2] not in ("tree", "blob") or len(parts) < 4:
            raise RemoteError("Use a repo URL, or .../tree/<ref>/<folder>, or .../blob/<ref>/<folder>/SKILL.md")
        ref = parts[3]
        rest = parts[4:]
        if parts[2] == "blob" and rest:
            rest = rest[:-1]  # a file URL means "the folder it lives in"
        sub = "/".join(rest)
        if not _REF.match(ref) or ".." in ref or ".." in sub.split("/"):
            raise RemoteError("Invalid ref or path in URL.")
    return GitHubRef(owner, repo, ref, sub)


class _NoAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward the GitHub token to a different host after a redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urlparse(newurl).netloc != urlparse(req.full_url).netloc:
            new.headers.pop("Authorization", None)
        return new


def _download(url: str, token: Optional[str]) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    opener = urllib.request.build_opener(_NoAuthOnRedirect)
    too_big = RemoteError("Archive is larger than 50 MB. Scan a subfolder instead, "
                          "e.g. github.com/<owner>/<repo>/tree/<ref>/<folder>")
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            length = resp.headers.get("Content-Length")
            if length and length.isdigit() and int(length) > MAX_DOWNLOAD:
                raise too_big
            buf, total = io.BytesIO(), 0
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DOWNLOAD:
                    raise too_big
                buf.write(chunk)
            return buf.getvalue()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise RemoteError("Not found. Check the URL (private repos need the GITHUB_TOKEN environment variable).")
        if e.code in (403, 429):
            raise RemoteError("GitHub refused the request (rate limit?). Set GITHUB_TOKEN to raise the limit.")
        raise RemoteError(f"GitHub returned HTTP {e.code}.")
    except urllib.error.URLError as e:
        raise RemoteError(f"Network error: {e.reason}")


def extract_zip_safely(data: bytes, dest: Path) -> None:
    """Extract without ever trusting names, links or declared sizes."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise RemoteError("Downloaded archive is not a valid zip file.")
    infos = zf.infolist()
    if len(infos) > MAX_FILES:
        raise RemoteError("Archive has too many files.")
    root = dest.resolve()
    root.mkdir(parents=True, exist_ok=True)
    written = 0
    for info in infos:
        if (info.external_attr >> 16) & 0o170000 == stat.S_IFLNK:
            continue                       # never create symlinks
        target = (root / info.filename).resolve()
        if target != root and root not in target.parents:
            continue                       # zip-slip: path escapes the folder
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as out:
            while True:
                chunk = src.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_UNPACKED:
                    raise RemoteError("Archive expands to more than 200 MB.")
                out.write(chunk)


def fetch_github(arg: str, dest: Path, token: Optional[str] = None) -> Fetched:
    ref = parse_github(arg)
    token = token or os.environ.get("GITHUB_TOKEN")
    if token:
        # Authenticated: use the API (works for private repos, higher rate limit).
        url = f"https://api.github.com/repos/{ref.owner}/{ref.repo}/zipball"
        if ref.ref:
            url += "/" + quote(ref.ref, safe="/")
    else:
        # Anonymous: plain archive URLs do not use the 60-requests/hour API quota.
        url = f"https://github.com/{ref.owner}/{ref.repo}/archive/{quote(ref.ref or 'HEAD', safe='/')}.zip"
    data = _download(url, token)
    extract_zip_safely(data, dest)

    entries = [p for p in Path(dest).iterdir()]
    root = entries[0] if len(entries) == 1 and entries[0].is_dir() else Path(dest)
    target = (root / ref.subpath) if ref.subpath else root
    resolved, base = target.resolve(), root.resolve()
    if (resolved != base and base not in resolved.parents) or not resolved.exists():
        raise RemoteError(f"Path not found in repository: {ref.subpath}")
    return Fetched(target, ref.label)
