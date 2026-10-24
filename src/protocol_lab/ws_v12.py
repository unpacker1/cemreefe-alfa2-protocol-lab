"""Clean-room Alfa2 v12 WebSocket payload shape; no actual network server."""
from __future__ import annotations
import math
import msgpack


class ContractError(ValueError):
    pass


def reliable(message: dict) -> bytes:
    if not isinstance(message, dict) or not isinstance(message.get("t"), str):
        raise ContractError("reliable message requires a string t")
    return b"\x00" + msgpack.packb(message, use_bin_type=True)


def parse_reliable(frame: bytes) -> dict:
    if not frame or frame[0] != 0:
        raise ContractError("not a reliable frame")
    try:
        obj = msgpack.unpackb(frame[1:], raw=False, strict_map_key=True)
    except (ValueError, msgpack.ExtraData, msgpack.FormatError, msgpack.StackError) as exc:
        raise ContractError("invalid MessagePack") from exc
    if not isinstance(obj, dict) or not isinstance(obj.get("t"), str):
        raise ContractError("expected typed MessagePack dictionary")
    return obj


def movement(rows: list[list[int | float]]) -> bytes:
    if not isinstance(rows, list) or len(rows) > 256:
        raise ContractError("movement requires at most 256 tuples")
    for row in rows:
        if not isinstance(row, list) or len(row) != 5:
            raise ContractError("movement tuple must have five elements")
        if type(row[0]) is not int or row[0] <= 0:
            raise ContractError("movement VID must be positive integer")
        if not all(type(x) in (int, float) and math.isfinite(x) for x in row[1:]):
            raise ContractError("movement values must be finite")
    return b"\x01" + msgpack.packb(rows, use_bin_type=True)


def parse_movement(frame: bytes) -> list:
    if not frame or frame[0] != 1:
        raise ContractError("not a movement frame")
    try:
        obj = msgpack.unpackb(frame[1:], raw=False)
    except (ValueError, msgpack.ExtraData, msgpack.FormatError, msgpack.StackError) as exc:
        raise ContractError("invalid MessagePack") from exc
    movement(obj)  # Validate shape without writing to the game world.
    return obj
