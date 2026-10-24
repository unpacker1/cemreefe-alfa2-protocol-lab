import struct
import unittest
from protocol_lab.gc import FrameError, IncrementalGCDecoder


def generate_stream():
    # Synthetic reproduction of the observed GC130/GC106/GC17/GC114/GC115 boundary failures.
    land = struct.pack("<BH", 130, 3 + 24 * 18) + bytes(24 * 18)
    server_time = struct.pack("<Bq", 106, 1760000000)
    point = struct.pack("<iIBii", 17, 42, 4, 300, 450)
    effect = struct.pack("<BBI", 114, 2, 42)
    npc = struct.pack("<BHH", 115, 5 + 78 * 47, 47) + bytes(78 * 47)
    return land + server_time + point + effect + npc


class GCRegression(unittest.TestCase):
    def test_full_trace_preserves_boundaries(self):
        d = IncrementalGCDecoder()
        frames = d.feed(generate_stream())
        self.assertEqual([x.opcode for x in frames], [130, 106, 17, 114, 115])
        self.assertEqual([x.wire_size for x in frames], [435, 9, 17, 6, 3671])
        self.assertEqual(frames[-1].detail['declared_count'], 47)
        d.finish()

    def test_every_fragment_split_matches_full_trace(self):
        data = generate_stream()
        for split in range(0, len(data) + 1):
            d = IncrementalGCDecoder()
            a = d.feed(data[:split])
            b = d.feed(data[split:])
            self.assertEqual([f.opcode for f in a + b], [130, 106, 17, 114, 115])
            d.finish()

    def test_bytewise_tcp_fragmentation(self):
        d = IncrementalGCDecoder()
        found = []
        for b in generate_stream():
            found.extend(d.feed(bytes((b,))))
        self.assertEqual([f.opcode for f in found], [130, 106, 17, 114, 115])
        d.finish()

    def test_bad_npc_count_is_invalid_frame_not_socket_error(self):
        p = struct.pack("<BHH", 115, 5 + 78 * 47, 18)
        with self.assertRaises(FrameError) as ctx:
            IncrementalGCDecoder().feed(p)
        self.assertEqual(ctx.exception.reason, "invalid_gc115_length")

    def test_truncated_npc_reported_only_at_eof(self):
        d = IncrementalGCDecoder()
        self.assertEqual(d.feed(struct.pack("<BHH", 115, 5 + 78 * 47, 47)), [])
        with self.assertRaises(FrameError) as ctx:
            d.finish()
        self.assertEqual(ctx.exception.reason, "game_frame_incomplete")

    def test_gc17_bad_high_header_bytes_rejected(self):
        with self.assertRaises(FrameError) as ctx:
            IncrementalGCDecoder().feed(bytes((17, 1, 0, 0)) + bytes(13))
        self.assertEqual(ctx.exception.reason, "invalid_gc17_header")

    def test_known_one_byte_zeros_bounded(self):
        d = IncrementalGCDecoder()
        self.assertEqual(len(d.feed(bytes(4))), 4)
        with self.assertRaises(FrameError) as ctx:
            d.feed(bytes(13))
        self.assertEqual(ctx.exception.reason, "excessive_zero_headers")

    def test_unknown_opcodes_fail_closed_with_numeric_trace_only(self):
        d = IncrementalGCDecoder()
        d.feed(struct.pack("<Bq", 106, 1760000000))
        with self.assertRaises(FrameError) as ctx:
            d.feed(bytes((244,)))
        self.assertEqual(ctx.exception.reason, "unsupported_live_opcode")
        self.assertEqual(ctx.exception.opcode, 244)
        self.assertEqual(ctx.exception.history, (106,))

    def test_500_npc_records_fit_true_16bit_wire_size(self):
        count = 500
        data = struct.pack("<BHH", 115, 5 + 78 * count, count) + bytes(78 * count)
        out = IncrementalGCDecoder().feed(data)
        self.assertEqual(out[0].wire_size, 39005)

    def test_packet_17_not_decoded_as_single_header(self):
        data = struct.pack("<iIBii", 17, 42, 4, 300, 450)
        self.assertEqual([x.wire_size for x in IncrementalGCDecoder().feed(data)], [17])

if __name__ == "__main__":
    unittest.main()
