import io
import json
import unittest
from unittest.mock import patch

from protocol_lab.triage import build_report, classify, main, safe_snapshot


class SafeHealthTriageTests(unittest.TestCase):
    def test_sanitized_gc115_disconnect_classification(self):
        raw = {
            "gatewayUptimeSeconds": 131,
            "lastNative": {
                "gameEntered": True, "welcomeVerified": True,
                "nativeSessionActive": False,
                "nativeDisconnectReason": "invalid_gc115_length",
                "nativeDisconnectOpcode": 115,
                "nativeDisconnectPreviousOpcode": 17,
                "nativeNpcDeclaredSize": 3671,
                "nativeNpcDeclaredCount": 18,
                "nativeNpcExpectedSize": 1409,
                "nativeRecentOpcodes": [106, 17, 114, 115],
                "secretToken": "PRIVATE_TEST_VALUE",
                "originalScriptBytesHex": "DEADBEEF",
                "databasePath": "DO_NOT_EXPORT",
            },
            "account": {"password": "DO_NOT_EXPORT"},
        }
        result = build_report(raw)
        self.assertEqual(result["classification"], "native_frame_size_or_alignment")
        safe = result["safeSnapshot"]
        self.assertEqual(safe["nativeDisconnectOpcode"], 115)
        self.assertEqual(safe["nativeNpcDeclaredCount"], 18)
        self.assertNotIn("account", safe)
        self.assertNotIn("secretToken", safe)
        self.assertNotIn("originalScriptBytesHex", safe)
        self.assertNotIn("databasePath", safe)
        report_text = json.dumps(result)
        for marker in ("PRIVATE_TEST_VALUE", "DEADBEEF", "DO_NOT_EXPORT"):
            self.assertNotIn(marker, report_text)

    def test_known_gc114_and_69_timeout_diagnoses(self):
        data = {"lastNative": {
            "nativeSessionActive": False, "welcomeVerified": True,
            "nativeDisconnectReason": "unsupported_live_opcode",
            "nativeDisconnectOpcode": 114,
            "nativeSpecialEffectPackets": 2,
        }}
        self.assertEqual(build_report(data)["classification"],
                         "unsupported_native_gc_frame")
        data["lastNative"]["nativeDisconnectReason"] = "game_read_timeout"
        self.assertEqual(build_report(data)["classification"],
                         "native_read_timeout")
        data["lastNative"]["nativeDisconnectReason"] = "game_frame_incomplete"
        self.assertEqual(build_report(data)["classification"],
                         "native_truncated_frame")

    def test_connected_and_browser_exit_are_distinguished(self):
        self.assertEqual(classify({"nativeSessionActive": True}), "connected")
        self.assertEqual(classify({
            "welcomeVerified": True, "webSocketCloseCause": "browser_closed"
        }), "browser_websocket_closed")

    def test_untrusted_reason_and_close_cause_are_redacted(self):
        data = {"lastNative": {
            "nativeDisconnectReason": "user@example.com SECRET DO_NOT_COPY",
            "webSocketCloseCause": "private-record DO_NOT_COPY",
            "nativeDisconnectStage": "illegal stage DO_NOT_COPY",
            "nativeReadExpected": 8,
        }}
        safe = safe_snapshot(data)
        self.assertEqual(safe["nativeDisconnectReason"], "redacted_unrecognized")
        self.assertEqual(safe["webSocketCloseCause"], "redacted_unrecognized")
        self.assertNotIn("nativeDisconnectStage", safe)
        self.assertNotIn("DO_NOT_COPY", repr(safe))

    def test_rejects_negative_nan_oversized_and_bool_as_numbers(self):
        values = {
            "nativeDisconnectOpcode": 900,
            "nativeReadExpected": True,
            "nativeReadReceived": -1,
            "nativeLivePacketCount": 10**12,
            "nativeRecentOpcodes": [1, -1, 114],
            "welcomeVerified": 1,
        }
        safe = safe_snapshot({"lastNative": values})
        for key in values:
            self.assertNotIn(key, safe)

    def test_last_native_can_be_missing(self):
        self.assertEqual(safe_snapshot({"serviceName": "not exported"}), {})
        with self.assertRaises(ValueError):
            safe_snapshot("not an object")

    def test_cli_never_prints_unsanitized_json(self):
        data = {"lastNative": {
            "welcomeVerified": True,
            "nativeSessionActive": False,
            "nativeDisconnectOpcode": 115,
            "secret": "DO_NOT_PRINT",
        }}
        stdout = io.StringIO()
        with patch("sys.stdin", io.StringIO(json.dumps(data))), \
             patch("sys.stdout", stdout):
            self.assertEqual(main(), 0)
        self.assertIn("nativeDisconnectOpcode", stdout.getvalue())
        self.assertNotIn("DO_NOT_PRINT", stdout.getvalue())

    def test_cli_rejects_malformed_input_without_echo(self):
        out = io.StringIO()
        err = io.StringIO()
        with patch("sys.stdin", io.StringIO("PRIVATE_BROKEN_JSON{")), \
             patch("sys.stdout", out), patch("sys.stderr", err):
            self.assertEqual(main(), 2)
        self.assertEqual(out.getvalue(), "")
        self.assertNotIn("PRIVATE_BROKEN_JSON", err.getvalue())


if __name__ == "__main__":
    unittest.main()
