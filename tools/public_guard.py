#!/usr/bin/env python3
"""Fail closed: publish exactly the hand-authored clean-room files listed here.

Important: only this NEW repository's worktree is scanned. Never run it
against the originals to whitelist their contents automatically.
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

ALLOW = {
    ".gitignore", ".gitattributes", "README.md", "SECURITY.md", "MIGRATION.md",
    "STATUS.md", "pyproject.toml", "publish_public.sh",
    ".github/workflows/protocol-ci.yml",
    "cpp/frame_contract.hpp", "cpp/test_frame_contract.cpp",
    "src/protocol_lab/__init__.py", "src/protocol_lab/gc.py",
    "src/protocol_lab/ws_v12.py", "src/protocol_lab/session.py",
    "src/protocol_lab/triage.py", "src/protocol_lab/game_exit.py",
    "src/protocol_lab/source_audit.py",
    "tests/test_gc.py", "tests/test_ws_session.py", "tests/test_triage.py",
    "tests/test_game_exit.py", "tests/test_source_audit.py",
    "tools/public_guard.py", "fixtures/observed_failure_types.synthetic.json",
}

DENY_SUFFIX = {
    ".apk", ".aab", ".ipa", ".obb", ".db", ".sqlite", ".sqlite3",
    ".sql", ".zip", ".7z", ".rar", ".gr2", ".dds", ".glb",
    ".msm", ".epk", ".eix", ".p12", ".key", ".pem", ".jks",
    ".keystore", ".log", ".png", ".jpg", ".mp4",
}

def check(root: Path) -> list[str]:
    problems = []
    actual = set()
    for p in root.rglob("*"):
        parts = p.relative_to(root).parts
        if ".git" in parts or "__pycache__" in parts or any(
            v.endswith(".egg-info") or v in (".venv", ".pytest_cache") for v in parts
        ):
            continue  # Generated/ignored Python metadata is never staged by Git.
        if p.is_dir():
            continue
        rel = p.relative_to(root).as_posix()
        actual.add(rel)
        if p.is_symlink() or not p.is_file():
            problems.append(f"unexpected non-regular file: {rel}")
            continue
        if rel not in ALLOW:
            problems.append(f"not on explicit public allowlist: {rel}")
            continue
        if p.suffix.lower() in DENY_SUFFIX or p.name.startswith(".env"):
            problems.append(f"forbidden file type: {rel}")
        if p.stat().st_size > 180_000:
            problems.append(f"unusually large text file: {rel}")
            continue
        try:
            content = p.read_text(encoding="utf-8")
        except UnicodeError:
            problems.append(f"binary content in public file: {rel}")
            continue
        if rel == "tools/public_guard.py":
            continue  # Own rule examples must not trigger scanner itself.
        secret_markers = [
            "ghp" + "_", "github" + "_pat_", "AK" + "IA", "BEGIN PRIVATE KEY",
            "sk" + "-proj-", "sk" + "-live-", "Bearer " + "eyJ",
        ]
        if any(marker in content for marker in secret_markers):
            problems.append(f"possible token/private key: {rel}")
        # Never embed private original tree paths in public examples.
        if re.search(r"/data/data/com\.termux/files/home/(?:storage|CEMREEFE)", content):
            problems.append(f"private device path: {rel}")
    missing = ALLOW - actual
    problems.extend(f"missing required public file: {v}" for v in sorted(missing))
    return problems


if __name__ == "__main__":
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    errors = check(root)
    for error in errors:
        print("[BLOCK]", error)
    print("[PUBLIC GUARD]", "PASS" if not errors else "FAIL",
          "-- strict allowlist + token/dangerous file guard")
    sys.exit(bool(errors))
