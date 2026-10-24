import math
import unittest
from protocol_lab.ws_v12 import reliable, parse_reliable, movement, parse_movement, ContractError
from protocol_lab.session import GameSession, SessionError


class WebSocketContractTest(unittest.TestCase):
    def test_hello_and_welcome_reliable_channel(self):
        for message in ({"t": "Hello", "version": 12, "character": 1, "token": "TEST_ONLY"},
                        {"t": "Welcome", "me": {"id": 1, "x": 0, "y": 0}}):
            self.assertEqual(parse_reliable(reliable(message)), message)

    def test_unreliable_movement_shape(self):
        sample = [[10001, 5000, 7000, math.pi / 2, 1]]
        self.assertEqual(parse_movement(movement(sample)), sample)

    def test_invalid_nan_and_wrong_channels(self):
        with self.assertRaises(ContractError):
            movement([[1, float("nan"), 2, 3, 1]])
        with self.assertRaises(ContractError):
            parse_reliable(movement([[1, 2, 3, 4, 1]]))
        with self.assertRaises(ContractError):
            parse_movement(reliable({"t": "Ping"}))

    def test_key_consumed_even_when_game_disconnects(self):
        s = GameSession()
        s.begin(hello_version=12, owned=True)
        s.enter_game()
        s.welcome()
        s.disconnect("game_frame_incomplete")
        self.assertEqual(s.state, "CLOSED")
        self.assertTrue(s.welcome_verified)
        with self.assertRaisesRegex(SessionError, "fresh_native_game_key_required"):
            s.reconnect_with_same_game_key()

    def test_unauthorized_hello_cannot_consume_native_key(self):
        s = GameSession()
        with self.assertRaises(SessionError):
            s.begin(hello_version=12, owned=False)
        self.assertFalse(s.native_key_consumed)

if __name__ == "__main__":
    unittest.main()
