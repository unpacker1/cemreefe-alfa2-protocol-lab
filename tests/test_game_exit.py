"""Synthetic game-peer EOF and process diagnostics, no authentic logs."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from protocol_lab.game_exit import (
    classify_peer, inspect, safe_log_counts, safe_port_probe,
    safe_keepalive_config, report_indicators,
)


class SafeLocalGameExitTests(unittest.TestCase):
    def test_eof_listener_still_online_not_misclassified_as_crash(self):
        health = {"lastNative": {"welcomeVerified": True,
                                 "nativeSessionActive": False,
                                 "nativeDisconnectReason": "game_peer_eof",
                                 "nativeReadExpected": 1,
                                 "nativeReadReceived": 0}}
        self.assertEqual(classify_peer(health, {"game": True}),
                         "game_session_eof_listener_still_running")
        self.assertEqual(classify_peer(health, {"game": False}),
                         "game_listener_stopped_after_eof")

    def test_game_log_counts_do_not_expose_original_lines(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            logs = root / "logs"
            logs.mkdir()
            (logs / "channel1_core1.out").write_text(
                "2026-test disconnect player=SYNTHETIC_SENSITIVE_NAME\n"
                "test segmentation fault account=TEST_PRIVATE_VALUE\n"
                "test speedhack UNKNOWN_GAME_ID\n"
                "test ping timeout SECRET_SESSION_TOKEN\n",
                encoding="utf-8")
            summary = safe_log_counts(root)
            self.assertEqual(summary["filesExamined"], 1)
            self.assertEqual(summary["recentLogCategoryCounts"]["game_disconnect"], 1)
            self.assertEqual(summary["recentLogCategoryCounts"]["game_process_fault"], 1)
            self.assertEqual(summary["recentLogCategoryCounts"]["game_timeout"], 1)
            self.assertEqual(summary["recentLogCategoryCounts"]["game_security_reject"], 1)
            result = json.dumps(summary)
            self.assertNotIn("SYNTHETIC_SENSITIVE_NAME", result)
            self.assertNotIn("SECRET_SESSION_TOKEN", result)
            self.assertNotIn("TEST_PRIVATE_VALUE", result)

    def test_realistic_game_ping_no_pong_is_counted_without_raw_user(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            logs = root / "channel1_core1" / "log"
            logs.mkdir(parents=True)
            (logs / "syslog").write_text(
                "PING_EVENT: no pong PRIVATE_USER_DEVICE_NAME\\n"
                "SYSTEM: closing socket. DESC #88\\n"
                "SEQUENCE 0xfee mismatch 0xff != 0x12 header 254\\n"
                "PONG! 1 12\\n".replace("\\n", "\n"),
                encoding="utf-8",
            )
            counts = safe_log_counts(root)["recentLogCategoryCounts"]
            self.assertEqual(counts["game_ping_no_pong"], 1)
            self.assertEqual(counts["game_timeout"], 1)
            self.assertEqual(counts["game_session_socket_closed"], 1)
            self.assertEqual(counts["game_sequence_mismatch"], 1)
            self.assertEqual(counts["game_pong_received"], 1)
            self.assertNotIn("PRIVATE_USER_DEVICE_NAME", json.dumps(counts))

    def test_duplicate_login_and_handshake_categories(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "logs").mkdir()
            (root / "logs" / "channel1_core1.out").write_text(
                "DisconnectOfSameLogin SECRET_ACCOUNT\\n"
                "handshake retry limit reached! SECRET_PLAYER\\n".replace("\\n", "\n")
            )
            info = safe_log_counts(root)
            self.assertEqual(info["recentLogCategoryCounts"]["game_duplicate_login"], 1)
            self.assertEqual(info["recentLogCategoryCounts"]["game_handshake_rejected"], 1)
            self.assertNotIn("SECRET_PLAYER", json.dumps(info))

    def test_server_keepalive_config_only_numeric_value_exposed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            game = root / "channel1_core1"
            game.mkdir()
            (game / "CONFIG").write_text(
                "DB_PASSWORD: NO_PRIVATE_PASSWORD_MAY_LEAK" + chr(10)
                + "ping_event_second_cycle: 60" + chr(10),
                encoding="utf-8"
            )
            result = safe_keepalive_config(root)
            self.assertEqual(result["serverPingIntervalSeconds"], 60)
            self.assertEqual(result["heartbeatConfigSource"], "local_game_config")
            self.assertNotIn("NO_PRIVATE_PASSWORD_MAY_LEAK", json.dumps(result))

    def test_server_keepalive_missing_does_not_assume_default(self):
        with tempfile.TemporaryDirectory() as temp:
            result = safe_keepalive_config(temp)
            self.assertIsNone(result["serverPingIntervalSeconds"])
            self.assertEqual(result["heartbeatConfigSource"], "unavailable")

    def test_server_keepalive_symlink_is_never_read(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            game = root / "channel1_core1"
            game.mkdir()
            secret = root / "conf_secret"
            secret.write_text("ping_event_second_cycle: 90")
            (game / "CONFIG").symlink_to(secret)
            self.assertIsNone(safe_keepalive_config(root)["serverPingIntervalSeconds"])

    def test_old_log_occurrences_only_return_uncorrelated_signals(self):
        counts = {
            "game_ping_no_pong": 1,
            "game_sequence_mismatch": 1,
            "game_duplicate_login": 0,
            "game_process_fault": 0,
            "game_handshake_rejected": 0,
        }
        signals = report_indicators(counts)
        self.assertTrue(signals["possibleNoPongDisconnect"])
        self.assertTrue(signals["possibleSequenceMismatch"])
        self.assertFalse(signals["possibleDuplicateLogin"])

    def test_no_logs_have_no_invented_events(self):
        with tempfile.TemporaryDirectory() as temp:
            info = safe_log_counts(temp)
            self.assertEqual(info["filesExamined"], 0)
            self.assertTrue(all(v == 0 for v in
                                info["recentLogCategoryCounts"].values()))

    def test_symlink_logs_are_not_read(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "logs").mkdir()
            secret = root / "private-text"
            secret.write_text("segmentation fault TEST_PRIVATE_VALUE")
            (root / "logs" / "channel1_core1.out").symlink_to(secret)
            info = safe_log_counts(root)
            self.assertEqual(info["filesExamined"], 0)

    def test_full_report_contains_only_sanitized_health(self):
        with tempfile.TemporaryDirectory() as temp:
            health = {"lastNative": {"welcomeVerified": True,
                         "nativeSessionActive": False,
                         "nativeDisconnectOpcode": 19,
                         "nativeRecentOpcodes": [123, 123, 127, 19],
                         "nativeDisconnectReason": "game_peer_eof",
                         "password": "PRIVATE_PASSWORD_DO_NOT_OUTPUT"},
                      "accountSecret": "PRIVATE_ACCOUNT_DO_NOT_OUTPUT"}
            with patch("protocol_lab.game_exit.safe_port_probe",
                       return_value={"db": True, "auth": True, "game": True}):
                result = inspect(health, temp)
            self.assertEqual(result["classification"],
                             "game_session_eof_listener_still_running")
            self.assertEqual(result["safeHealth"]["safeSnapshot"]
                             ["nativeRecentOpcodes"], [123, 123, 127, 19])
            report = json.dumps(result)
            self.assertNotIn("PRIVATE_PASSWORD_DO_NOT_OUTPUT", report)
            self.assertNotIn("PRIVATE_ACCOUNT_DO_NOT_OUTPUT", report)

    def test_probe_refuses_external_hosts(self):
        with self.assertRaises(ValueError):
            safe_port_probe("192.0.2.4")


if __name__ == "__main__":
    unittest.main()
