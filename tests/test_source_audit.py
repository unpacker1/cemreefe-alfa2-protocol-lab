import json
import tempfile
import unittest
from pathlib import Path
from protocol_lab.source_audit import audit_native_decoder


class SafeNativeSourceAuditTests(unittest.TestCase):
    def test_only_private_source_syntax_flags_not_raw_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "native_cipher_live.cpp"
            p.write_text(
                'char privateKey[]="DO_NOT_EMIT_OR_EXPORT";\n'
                'unsigned zero_header_run=0;\n'
                'if(head==44) {if(!send_pong())return 70;}\n'
                'else if(head==255) { /* GC handshake */ }\n'
                'else if(head==252) { /* GC time sync */ }\n'
                'const unsigned actual=6u+((flags&64u)?25u:0u);\n'
                'if(!drain_decrypted(actual-6u))return 70;\n')
            flags = audit_native_decoder(tmp)
            self.assertTrue(flags["sourcePresent"])
            self.assertTrue(flags["pingGc44HandlerPresent"])
            self.assertTrue(flags["gameHandshakeGc255HandlerPresent"])
            self.assertTrue(flags["timeSyncGc252HandlerPresent"])
            self.assertTrue(flags["questGc81FlagLengthLogicPresent"])
            self.assertNotIn("DO_NOT_EMIT_OR_EXPORT", json.dumps(flags))
            self.assertFalse(flags["sourceCodeModified"])
            self.assertFalse(flags["compiledBinaryVerified"])

    def test_initial_handshake_does_not_count_for_live_game(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "native_cipher_live.cpp"
            p.write_text(
                'if(head==255) { /* initial only */ }\n'
                'unsigned zero_header_run=0;\n'
                'if(head==44) {send_pong();}\n')
            flags = audit_native_decoder(tmp)
            self.assertFalse(flags["gameHandshakeGc255HandlerPresent"])
            self.assertTrue(flags["pingGc44HandlerPresent"])

    def test_nonexistent_private_source_does_not_fabricate_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            flags = audit_native_decoder(tmp)
            self.assertFalse(flags["sourcePresent"])
            self.assertFalse(flags["postGameParserFound"])

    def test_symlink_to_secret_source_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = root / "source-private.cpp"
            secret.write_text("unsigned zero_header_run=0; if(head==255){}")
            (root / "native_cipher_live.cpp").symlink_to(secret)
            flags = audit_native_decoder(root)
            self.assertFalse(flags["sourcePresent"])
            self.assertNotIn("source-private.cpp", str(flags))


if __name__ == "__main__":
    unittest.main()
