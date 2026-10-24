"""Local-only process/port diagnostic for original GAME EOF.

This is a clean-room tool. It NEVER uploads, prints, stores or commits raw
server logs, account details, credentials, IPs or packet payloads.
The caller supplies the location of its PRIVATE runtime on the phone.
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path
from protocol_lab.triage import build_report

CATEGORIES = {
    "game_ping_no_pong": r"PING_EVENT\s*:\s*no\s+pong",
    "game_pong_received": r"\bPONG!\s+\d+\s+\d+",
    "game_sequence_mismatch": r"\bSEQUENCE\b[^\n]{0,160}\bmismatch\b",
    "game_duplicate_login": r"(?:same\s*login|different\s*computer|duplicate\s*login|DisconnectOfSameLogin)",
    "game_session_socket_closed": r"SYSTEM\s*:\s*closing\s+socket",
    "game_handshake_rejected": r"(?:invalid\s+handshake|handshake\s+retry\s+limit)",
    "game_client_version_rejected": r"(?:VERSION_CONFLICT|client version[^\n]{0,80}(?:mismatch|wrong)|incorrect client version)",
    "game_server_phase_close": r"(?:SetPhase\s*\(\s*PHASE_CLOSE|PHASE_CLOSE)",
    "game_process_fault": r"(?:segmentation fault|sigsegv|core dumped|fatal error|abort(?:ed)?|assertion failed)",
    "game_disconnect": r"(?:disconnect|disconnected|connection closed|close socket|close desc|connection reset)",
    "game_timeout": r"(?:timed?[\s_-]*out|no ping|no pong|ping timeout|heartbeat|keepalive)",
    "game_login_reject": r"(?:login fail|invalid login|auth fail|wrong login|login key|duplicate login)",
    "game_security_reject": r"(?:speed.?hack|hack.?log|crc mismatch|invalid packet|sequence error|invalid header)",
    "game_shutdown": r"(?:shutdown|server stopped|quitting|terminat(?:ion|ed))",
}
PORTS = {"db": 9000, "auth": 11000, "game": 11011}


def safe_port_probe(host="127.0.0.1", timeout=0.25):
    if host != "127.0.0.1":
        raise ValueError("Only local loopback allowed")
    out = {}
    for name, port in PORTS.items():
        try:
            with socket.create_connection((host, port), timeout=timeout):
                out[name] = True
        except OSError:
            out[name] = False
    return out


def _safe_tail(path: Path, max_bytes=65536):
    if path.is_symlink() or not path.is_file():
        return None
    try:
        with path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - max_bytes))
            return fh.read(max_bytes).decode("utf-8", "replace")
    except OSError:
        return None


def safe_log_counts(runtime):
    """Only counts of error categories; never log excerpts."""
    root = Path(runtime).expanduser()
    # Avoid recursive scans and path traversal. Only known local log slots.
    relative = (
        # Source-exact paths from Cemreefe native_runtime_stage.py.
        # CWD/syslog.log and CWD/syserr.log are symlinks to these canonical
        # files; inspect targets directly (never follow symlinks).
        "logs/channel1_core1.syslog.log",
        "logs/channel1_core1.syserr.log",
        "logs/channel1_core1.out",
        "channel1_core1/stdout",
        "channel1_core1/stderr",
        # AUTH may explain same-login disconnects; keep separate counts.
        "logs/auth.syslog.log",
        "logs/auth.syserr.log",
        "logs/auth.out",
    )
    counts = dict.fromkeys(CATEGORIES, 0)
    game_counts = dict.fromkeys(CATEGORIES, 0)
    auth_counts = dict.fromkeys(CATEGORIES, 0)
    examined = []
    for name in relative:
        tail = _safe_tail(root / name)
        if tail is None:
            continue
        examined.append(name)
        own_counts = auth_counts if name.startswith("logs/auth.") else game_counts
        for kind, expression in CATEGORIES.items():
            found = len(re.findall(expression, tail, re.IGNORECASE))
            counts[kind] += found
            own_counts[kind] += found
    return {"filesExamined": len(examined),
            "knownLogFilesExamined": examined,
            "recentLogCategoryCounts": counts,
            "recentGameLogCategoryCounts": game_counts,
            "recentAuthLogCategoryCounts": auth_counts,
            "gameLogsFound": any(x.startswith("logs/channel1_core1.") or
                                 x.startswith("channel1_core1/") for x in examined),
            "logTailWindowBytesPerFile": 65536,
            "rawServerLogIncluded": False}


def safe_keepalive_config(runtime):
    """Extract only a verified numeric GAME heartbeat setting, never CONFIG text."""
    root = Path(runtime).expanduser()
    path = root / "channel1_core1" / "CONFIG"
    if path.is_symlink() or not path.is_file():
        return {"serverPingIntervalSeconds": None,
                "heartbeatConfigSource": "unavailable"}
    try:
        if path.stat().st_size > 131072:
            return {"serverPingIntervalSeconds": None,
                    "heartbeatConfigSource": "oversized_rejected"}
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"serverPingIntervalSeconds": None,
                "heartbeatConfigSource": "unreadable"}
    m = re.findall(
        r"(?im)^\s*ping_event_second_cycle\s*[:=]?\s*(\d{1,4})\s*$",
        text)
    if len(m) == 1 and 5 <= int(m[0]) <= 3600:
        return {"serverPingIntervalSeconds": int(m[0]),
                "heartbeatConfigSource": "local_game_config"}
    return {"serverPingIntervalSeconds": None,
            "heartbeatConfigSource": "not_explicitly_configured"}


def report_indicators(log_counts):
    """Uncorrelated log signatures are hypotheses, not a definite kick cause."""
    signals = {
        "possibleNoPongDisconnect": "game_ping_no_pong",
        "possibleSequenceMismatch": "game_sequence_mismatch",
        "possibleDuplicateLogin": "game_duplicate_login",
        "possibleHandshakeRejection": "game_handshake_rejected",
        "possibleGameProcessFault": "game_process_fault",
    }
    return {label: log_counts.get(category, 0) > 0
            for label, category in signals.items()}


def classify_peer(health, ports):
    safe = build_report(health)
    if safe["classification"] != "native_peer_closed":
        return safe["classification"]
    if ports["game"] is False:
        return "game_listener_stopped_after_eof"
    if ports["game"] is True:
        return "game_session_eof_listener_still_running"
    return "game_peer_closed_port_unknown"


def inspect(health, runtime):
    ports = safe_port_probe()
    safe = build_report(health)
    logs = safe_log_counts(runtime)
    return {
        "schema": "public_protocol_lab_local_game_exit_v1",
        "classification": classify_peer(health, ports),
        "safeHealth": safe,
        "localPortsOpen": ports,
        "localServerLogs": logs,
        "localKeepaliveConfig": safe_keepalive_config(runtime),
        "logSignalsUncorrelated": report_indicators(logs["recentLogCategoryCounts"]),
        "note": "Log keyword counts may include earlier sessions; signals are NOT proven causes.",
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", type=Path, required=True,
                    help="Private native runtime directory (only read locally)")
    args = ap.parse_args(argv)
    try:
        with urllib.request.urlopen(
                "http://127.0.0.1:8766/api/health", timeout=3) as response:
            health = json.load(response)
        report = inspect(health, args.runtime)
    except (OSError, urllib.error.URLError, ValueError, TypeError,
            json.JSONDecodeError):
        print(json.dumps({"schema": "public_protocol_lab_local_game_exit_v1",
                          "classification": "health_api_unavailable",
                          "localPortsOpen": safe_port_probe(),
                          "localServerLogs": safe_log_counts(args.runtime),
                          "rawDataExposed": False}, indent=2))
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
