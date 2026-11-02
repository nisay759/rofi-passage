"""Exceptions shared by the modules.

Messages end up in notifications (NTF-1), so they must never contain a secret:
only entry names, tool names and outcomes (SEC-9).
"""


class RofiPassageError(Exception):
    """An error reported to the user as a notification."""


class Cancelled(RofiPassageError):
    """The user dismissed a menu or a prompt; stop without side effects."""

    def __init__(self, message: str = "Cancelled") -> None:
        super().__init__(message)
