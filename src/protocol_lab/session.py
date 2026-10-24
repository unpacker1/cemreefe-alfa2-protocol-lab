"""Synthetic lifecycle used to reproduce single-use GAME key/reset confusion."""
from __future__ import annotations
from dataclasses import dataclass


class SessionError(ValueError):
    pass


@dataclass
class GameSession:
    state: str = "NEW"
    native_key_consumed: bool = False
    welcome_verified: bool = False
    disconnect_cause: str | None = None

    def begin(self, *, hello_version: int, owned: bool) -> None:
        if self.state != "NEW" or hello_version != 12 or not owned:
            raise SessionError("invalid_or_unauthorized_hello")
        self.state = "HELLO_VERIFIED"

    def enter_game(self) -> None:
        if self.state != "HELLO_VERIFIED" or self.native_key_consumed:
            raise SessionError("fresh_native_game_key_required")
        self.native_key_consumed = True
        self.state = "GAME_ENTERED"

    def welcome(self) -> None:
        if self.state != "GAME_ENTERED":
            raise SessionError("game_not_entered")
        self.welcome_verified = True
        self.state = "ACTIVE"

    def disconnect(self, reason: str) -> None:
        self.disconnect_cause = reason
        self.state = "CLOSED"

    def reconnect_with_same_game_key(self) -> None:
        if self.native_key_consumed:
            raise SessionError("fresh_native_game_key_required")
        raise SessionError("not_authenticated")
