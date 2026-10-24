"""Clean-room source-verified GAME keepalive framing contract.

Not network code; no keys, real packets or private server data. The original
Metin2 game client responds to GC_HANDSHAKE (255, 13 bytes) with sequenced
CG_TIME_SYNC (252, 14 bytes) and a one-byte GC_TIME_SYNC ack (252).
"""
import struct


def build_time_sync_response(handshake_packet: bytes, sequence_byte: int) -> bytes:
    if not isinstance(handshake_packet, bytes) or len(handshake_packet) != 13:
        raise ValueError("expected exactly 13 source-defined GC_HANDSHAKE bytes")
    if handshake_packet[0] != 255:
        raise ValueError("expected GC_HANDSHAKE opcode 255")
    if type(sequence_byte) is not int or not 0 <= sequence_byte <= 255:
        raise ValueError("expected sequence byte 0..255")
    token, server_time, delta = struct.unpack_from("<IIi", handshake_packet, 1)
    reply_time = (server_time + 2 * delta) & 0xFFFFFFFF
    # CPacketInfoCG: CG_TIME_SYNC uses sequence=true.
    return struct.pack("<BIIiB", 252, token, reply_time, 0, sequence_byte)


def is_game_time_sync_ack(packet: bytes) -> bool:
    return type(packet) is bytes and packet == b"\xfc"
