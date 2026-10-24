"""Safe, read-only native GAME health triage for the public regression lab.

The caller fetches its own PRIVATE localhost health object. This module
returns only bounded diagnostic counters and a reason drawn from a small
allowlist. It never sends network requests or writes the raw response.
Do NOT commit actual raw health JSON or native packet captures.
"""
from __future__ import annotations

import json
import sys

BOOLEAN_KEYS = (
    "gameEntered", "welcomeVerified", "nativeSessionActive",
    "requiresFreshLogin",
)
NUMBER_KEYS = (
    "nativeDisconnectOpcode", "nativeDisconnectPreviousOpcode",
    "nativeReadExpected", "nativeReadReceived", "nativeSocketErrno",
    "nativeLivePacketCount", "nativeNpcDeclaredSize",
    "nativeNpcDeclaredCount", "nativeNpcExpectedSize",
    "nativeLandListPackets", "nativeLandListRecords",
    "nativeZeroHeaderCount", "nativeZeroAfterOpcode",
    "nativeSpecialEffectPackets", "nativeNpcPositionPacketsLive",
    "nativeGamePingReceived", "nativeGamePongSent",
    "nativeGameHandshakeReceived", "nativeGameTimeSyncSent",
    "nativeGameTimeSyncAcknowledged",
)
REASONS = frozenset({
    "unsupported_live_opcode", "invalid_gc115_length",
    "invalid_gc17_header", "invalid_gc130_length",
    "game_frame_incomplete", "game_peer_eof",
    "game_read_timeout", "game_socket_io_error",
    "excessive_zero_headers", "native_process_exited",
    "native_connection_closed", "game_invalid_frame",
})
STAGES = frozenset({
    "game_header", "game_frame_body", "gc115_header",
    "gc115_payload", "gc17_payload", "gc_actor_add",
    "gc_actor_del", "gc_actor_move", "socket_poll_hup",
    "game_pong",
})
CLOSE_CAUSES = frozenset({
    "browser_closed", "client_close", "native_process_exit",
    "EOFError", "ConnectionError", "TimeoutError",
    "OSError", "ValueError", "TypeError",
})


def safe_snapshot(health: object) -> dict:
    """Discard *all* unknown/untrusted fields, even nested secrets."""
    if not isinstance(health, dict):
        raise ValueError("health must be a JSON object")
    data = health.get("lastNative")
    if not isinstance(data, dict):
        data = {}
    clean = {}
    uptime = health.get("gatewayUptimeSeconds")
    if type(uptime) is int and 0 <= uptime <= 10**9:
        clean["gatewayUptimeSeconds"] = uptime
    for key in BOOLEAN_KEYS:
        if type(data.get(key)) is bool:
            clean[key] = data[key]
    for key in NUMBER_KEYS:
        value = data.get(key)
        if type(value) is int and 0 <= value <= 10**9:
            if "Opcode" in key or key == "nativeZeroAfterOpcode":
                if value > 255:
                    continue
            clean[key] = value
    reason = data.get("nativeDisconnectReason")
    if isinstance(reason, str):
        clean["nativeDisconnectReason"] = (
            reason if reason in REASONS else "redacted_unrecognized"
        )
    stage = data.get("nativeDisconnectStage")
    if isinstance(stage, str) and stage in STAGES:
        clean["nativeDisconnectStage"] = stage
    cause = data.get("webSocketCloseCause")
    if isinstance(cause, str):
        clean["webSocketCloseCause"] = (
            cause if cause in CLOSE_CAUSES else "redacted_unrecognized"
        )
    recent = data.get("nativeRecentOpcodes")
    if (type(recent) is list and len(recent) <= 16 and
            all(type(v) is int and 0 <= v <= 255 for v in recent)):
        clean["nativeRecentOpcodes"] = recent[:]
    return clean


def classify(snapshot: dict) -> str:
    if snapshot.get("nativeSessionActive") is True:
        return "connected"
    reason = snapshot.get("nativeDisconnectReason")
    if reason == "unsupported_live_opcode":
        return "unsupported_native_gc_frame"
    if reason in ("invalid_gc115_length", "invalid_gc17_header",
                  "invalid_gc130_length", "game_invalid_frame"):
        return "native_frame_size_or_alignment"
    if reason == "game_frame_incomplete":
        return "native_truncated_frame"
    if reason == "game_peer_eof":
        return "native_peer_closed"
    if reason == "game_read_timeout":
        return "native_read_timeout"
    if reason == "excessive_zero_headers":
        return "native_stream_alignment_unverified"
    if snapshot.get("webSocketCloseCause") in ("browser_closed", "client_close"):
        return "browser_websocket_closed"
    if snapshot.get("gameEntered") is False:
        return "before_native_game"
    if snapshot.get("welcomeVerified") is True:
        return "post_welcome_disconnect_unknown"
    return "not_enough_diagnostics"


def build_report(raw_health: object) -> dict:
    clean = safe_snapshot(raw_health)
    return {"schema": "public_protocol_lab_safe_health_v1",
            "classification": classify(clean),
            "safeSnapshot": clean,
            "containsRawPacketBytes": False,
            "containsCredentials": False}


def main() -> int:
    # Input from stdin only; never fetch or store private health inside CI.
    raw = sys.stdin.read(131073)
    if len(raw) > 131072:
        print("Input rejected: oversized diagnostic object", file=sys.stderr)
        return 2
    try:
        report = build_report(json.loads(raw))
    except (ValueError, TypeError):
        print("Input rejected: invalid JSON health object", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
