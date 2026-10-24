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

    def test_gc81_stale_header_does_not_parse_quest_text_as_gc115(self):
        # Entirely synthetic: published fork bug retains six-byte size
        # while flags require a 31-byte quest title.
        quest = struct.pack("<BHHB", 81, 6, 7, 2) + b"sleep" + bytes(26)
        npc = struct.pack("<BHH", 115, 5 + 78 * 2, 2) + bytes(78 * 2)
        data = quest + npc
        decoder = IncrementalGCDecoder()
        result = decoder.feed(data)
        self.assertEqual([p.opcode for p in result], [81, 115])
        self.assertEqual([p.wire_size for p in result], [37, 161])
        self.assertEqual(result[0].detail["declared_size"], 6)
        self.assertEqual(result[0].detail["actual_size"], 37)
        decoder.finish()

    def test_gc81_stale_header_arbitrary_tcp_fragmentation(self):
        quest = struct.pack("<BHHB", 81, 6, 3, 2) + b"sleep" + bytes(26)
        point = struct.pack("<iIBii", 17, 42, 4, 300, 450)
        combined = quest + point
        for position in range(len(combined) + 1):
            with self.subTest(split=position):
                decoder = IncrementalGCDecoder()
                result = decoder.feed(combined[:position])
                result.extend(decoder.feed(combined[position:]))
                self.assertEqual([x.opcode for x in result], [81, 17])
                decoder.finish()

    def test_gc81_flag_payload_sum_accepts_declared_actual(self):
        fields = (1, 31, 17, 4, 17, 4, 25)
        for bit in range(7):
            with self.subTest(flag_bit=bit):
                length = 6 + fields[bit]
                quest = struct.pack("<BHHB", 81, length, 2, 1 << bit)
                decoder = IncrementalGCDecoder()
                result = decoder.feed(quest + bytes(fields[bit]))
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0].wire_size, length)
                decoder.finish()

    def test_gc81_rejects_unknown_flag_bits_and_bad_lengths(self):
        bad_flag = struct.pack("<BHHB", 81, 6, 1, 128)
        wrong_size = struct.pack("<BHHB", 81, 25, 1, 2)
        for data, reason in (
            (bad_flag, "invalid_gc81_flags"),
            (wrong_size, "invalid_gc81_length"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaises(FrameError) as ctx:
                    IncrementalGCDecoder().feed(data)
                self.assertEqual(ctx.exception.reason, reason)

    def test_gc81_incomplete_flagged_body_waits_for_more(self):
        decoder = IncrementalGCDecoder()
        quest = struct.pack("<BHHB", 81, 6, 2, 2)
        self.assertEqual(decoder.feed(quest + b"sleep"), [])
        with self.assertRaises(FrameError) as ctx:
            decoder.finish()
        self.assertEqual(ctx.exception.reason, "game_frame_incomplete")

    def test_source_exact_game_ping_handshake_time_sync_sizes(self):
        # Source: game/desc.cpp emits one-byte GC_PING, then 13-byte
        # GC_HANDSHAKE. A successful time-sync may emit one-byte 0xfc.
        ping = bytes((44,))
        handshake = struct.pack("<BIIi", 255, 123456, 9876543, 0)
        sync = bytes((252,))
        point = struct.pack("<iIBii", 17, 42, 4, 300, 450)
        data = ping + handshake + sync + point
        decoder = IncrementalGCDecoder()
        frames = decoder.feed(data)
        self.assertEqual([x.opcode for x in frames], [44, 255, 252, 17])
        self.assertEqual([x.wire_size for x in frames], [1, 13, 1, 17])
        decoder.finish()

    def test_fragmented_source_ping_handshake_never_becomes_fake_opcode(self):
        data = bytes((44,)) + struct.pack("<BIIi", 255, 123, 345, 0)
        data += struct.pack("<Bq", 106, 1760000000)
        for split in range(len(data)+1):
            with self.subTest(split=split):
                decoder = IncrementalGCDecoder()
                frames = decoder.feed(data[:split])
                frames.extend(decoder.feed(data[split:]))
                self.assertEqual([x.opcode for x in frames], [44, 255, 106])
                decoder.finish()

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
