"""Clean-room, ALREADY-DECRYPTED subset of a 64-bit Metin2-like GC wire.

This is a regression-test codec, not a complete game client. No encryption,
authentication, original assets, private implementation or real user data.
Frame sizes are subject to confirmation against the actual server fork.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from struct import unpack_from

# Only the cases verified in the project's synthetic regression set.
# ARM64 time_t=8, so GC_TIME is *9*, not 5. 17 uses a 4-byte header.
FIXED: dict[int, int] = {1: 35, 2: 5, 3: 24, 16: 1021,
                          17: 17, 76: 2551, 106: 9, 114: 6}
MAX_FRAME = 65535
MAX_BUFFER = 1_048_576


class FrameError(ValueError):
    def __init__(self, reason: str, opcode: int | None, history: tuple[int, ...]):
        super().__init__(f"{reason}: opcode={opcode} recent_opcodes={history}")
        self.reason = reason
        self.opcode = opcode
        self.history = history


@dataclass(frozen=True)
class Frame:
    opcode: int
    wire_size: int
    detail: dict[str, int | str]


class IncrementalGCDecoder:
    """Consumes arbitrary TCP fragments without guessing next frame offset."""
    def __init__(self):
        self.buffer = bytearray()
        self.history: deque[int] = deque(maxlen=16)
        self.last_opcode: int | None = None
        self.zero_run = 0
        self.zero_total = 0

    def _bad(self, reason: str, code: int | None = None) -> FrameError:
        return FrameError(reason, code, tuple(self.history))

    def feed(self, chunk: bytes) -> list[Frame]:
        if not isinstance(chunk, bytes):
            raise TypeError("decrypted bytes expected")
        if len(self.buffer) + len(chunk) > MAX_BUFFER:
            raise self._bad("buffer_limit", self.buffer[0] if self.buffer else None)
        self.buffer.extend(chunk)
        ready: list[Frame] = []
        while self.buffer:
            op = self.buffer[0]
            if op == 0:
                self.zero_run += 1
                self.zero_total += 1
                if self.zero_run > 16 or self.zero_total > 256:
                    raise self._bad("excessive_zero_headers", op)
                del self.buffer[:1]
                ready.append(Frame(op, 1, {"no_op": "single_byte"}))
                self.history.append(op)
                continue

            if op in FIXED:
                size = FIXED[op]
                detail: dict[str, int | str] = {}
                if op == 17 and len(self.buffer) >= 4 and self.buffer[1:4] != b"\x00" * 3:
                    raise self._bad("invalid_gc17_header", op)
            elif op == 81:
                # Synthetic compatibility for one published GAME fork:
                # QUEST_INFO's flagged fields can be written after a
                # six-byte header whose declared size remains six.
                if len(self.buffer) < 6:
                    break
                declared = unpack_from("<H", self.buffer, 1)[0]
                flags = self.buffer[5]
                field_sizes = (1, 31, 17, 4, 17, 4, 25)
                if flags & 0x80:
                    raise self._bad("invalid_gc81_flags", op)
                expected = 6 + sum(width for bit, width in
                                   enumerate(field_sizes) if flags & (1 << bit))
                if declared not in (6, expected):
                    raise self._bad("invalid_gc81_length", op)
                size = expected
                detail = {"declared_size": declared,
                          "flag": flags, "actual_size": expected}
            elif op in (115, 130):
                head_length = 5 if op == 115 else 3
                if len(self.buffer) < head_length:
                    break
                size = unpack_from("<H", self.buffer, 1)[0]
                detail = {"declared_size": size}
                if op == 115:
                    count = unpack_from("<H", self.buffer, 3)[0]
                    expected = 5 + 78 * count
                    detail.update(declared_count=count, expected_size=expected)
                    if size != expected:
                        raise self._bad("invalid_gc115_length", op)
                elif size < 3 or (size - 3) % 24:
                    raise self._bad("invalid_gc130_length", op)
                else:
                    detail["declared_count"] = (size - 3) // 24
                if size > MAX_FRAME:
                    raise self._bad("frame_overflow", op)
            else:
                raise self._bad("unsupported_live_opcode", op)

            if len(self.buffer) < size:
                break  # Wait for next TCP fragment; never resynchronize.
            del self.buffer[:size]
            ready.append(Frame(op, size, detail))
            self.history.append(op)
            self.last_opcode = op
            self.zero_run = 0
        return ready

    def finish(self) -> None:
        """Call at EOF to distinguish incomplete packet from clean shutdown."""
        if self.buffer:
            raise self._bad("game_frame_incomplete", self.buffer[0])
