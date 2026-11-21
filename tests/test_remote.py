import io
import stat
import zipfile
from pathlib import Path

import pytest

from skillaudit import cli
from skillaudit.remote import (Fetched, RemoteError, extract_zip_safely,
                               is_remote, parse_github)

ROOT = Path(__file__).resolve().parent.parent


def test_is_remote():
    assert is_remote("https://github.com/a/b")
    assert is_remote("github:a/b")
    assert not is_remote("./skills")
    assert not is_remote("C:\\skills")


def test_parse_repo_url():
    r = parse_github("https://github.com/owner/repo.git")
    assert (r.owner, r.repo, r.ref, r.subpath) == ("owner", "repo", None, "")


def test_parse_tree_and_blob():
    r = parse_github("https://github.com/o/r/tree/main/skills/foo")
    assert (r.ref, r.subpath) == ("main", "skills/foo")
    r = parse_github("https://github.com/o/r/blob/v1.0/skills/foo/SKILL.md")
    assert (r.ref, r.subpath) == ("v1.0", "skills/foo")
    assert parse_github("github:o/r").label == "github.com/o/r"


@pytest.mark.parametrize("bad", [
    "https://evil.com/o/r",
    "https://github.com/only-owner",
    "https://github.com/o/r/issues/5",
    "https://github.com/o/r/tree/main/../../etc",
    "https://github.com/o r/x",
])
def test_parse_rejects_bad(bad):
    with pytest.raises(RemoteError):
        parse_github(bad)


def _zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data, symlink in entries:
            info = zipfile.ZipInfo(name)
            if symlink:
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, data)
    return buf.getvalue()


def test_extract_blocks_zip_slip_and_symlinks(tmp_path):
    data = _zip([
        ("repo/ok.txt", "fine", False),
        ("../escaped.txt", "bad", False),
        ("repo/link", "/etc/passwd", True),
    ])
    dest = tmp_path / "out"
    extract_zip_safely(data, dest)
    assert (dest / "repo" / "ok.txt").read_text() == "fine"
    assert not (tmp_path / "escaped.txt").exists()
    assert not (dest / "repo" / "link").exists()


def test_extract_rejects_non_zip(tmp_path):
    with pytest.raises(RemoteError):
        extract_zip_safely(b"not a zip", tmp_path / "x")


def test_cli_scans_remote_and_relabels(monkeypatch, capsys):
    target = ROOT / "examples" / "risky-skill"
    monkeypatch.setattr(cli, "fetch_github",
                        lambda arg, dest, token=None: Fetched(target, "github.com/o/r"))
    code = cli.main(["audit", "https://github.com/o/r", "--no-color"])
    out = capsys.readouterr().out
    assert code == 1
    assert "github.com/o/r" in out and "DANGEROUS" in out


def test_cli_reports_remote_error(monkeypatch, capsys):
    def boom(arg, dest, token=None):
        raise RemoteError("Not found.")
    monkeypatch.setattr(cli, "fetch_github", boom)
    assert cli.main(["https://github.com/o/r"]) == 2
    assert "Not found." in capsys.readouterr().err
