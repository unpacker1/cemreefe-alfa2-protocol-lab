"""Read-only, privacy-preserving completeness check of a *local* GAME decoder.

Never copies, uploads, prints or stores original native source or assets.
It checks only syntactic presence of required post-GAME protocol branches.
Presence is not proof of correct behavior, successful compilation or server
acceptance. Works entirely offline, with an explicit local directory.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def audit_native_decoder(native_root):
    path = Path(native_root).expanduser() / "native_cipher_live.cpp"
    base = {
        "schema": "public_protocol_lab_native_source_flags_v1",
        "sourcePresent": False,
        "postGameParserFound": False,
        "pingGc44HandlerPresent": False,
        "gameHandshakeGc255HandlerPresent": False,
        "timeSyncGc252HandlerPresent": False,
        "questGc81FlagLengthLogicPresent": False,
        "sourceCodeIncluded": False,
        "sourceCodeModified": False,
        "compiledBinaryVerified": False,
    }
    try:
        if path.is_symlink() or not path.is_file():
            return base
        if path.stat().st_size > 2_000_000:
            return base
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return base
    base["sourcePresent"] = True
    # Scope to post-GAME loop, avoiding an initial handshake handler
    # being falsely counted as a *live* handler.
    split = source.find("unsigned zero_header_run")
    if split < 0:
        return base
    code = source[split:]
    base["postGameParserFound"] = True
    base["pingGc44HandlerPresent"] = bool(
        re.search(r"if\s*\(\s*head\s*==\s*44\s*\)", code)
        and "send_pong()" in code
    )
    base["gameHandshakeGc255HandlerPresent"] = bool(
        re.search(r"(?:\bhead\s*==\s*255\b|\bcase\s+255\s*:)", code)
    )
    base["timeSyncGc252HandlerPresent"] = bool(
        re.search(r"(?:\bhead\s*==\s*252\b|\bcase\s+252\s*:)", code)
    )
    base["questGc81FlagLengthLogicPresent"] = bool(
        "flags&64u" in code and "actual-6u" in code
    )
    return base


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--native-root", type=Path, required=True,
                        help="Path to private local native source directory")
    args = parser.parse_args(argv)
    print(json.dumps(audit_native_decoder(args.native_root),
                     indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
