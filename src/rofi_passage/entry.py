"""Parser and byte-faithful writer for the entry format contract.

The raw bytes are kept as a list of lines, newline included, so that removing a
line and joining the rest gives back every other byte untouched. Lines are
decoded with `surrogateescape` so invalid UTF-8 still round-trips.
"""

from __future__ import annotations

from dataclasses import dataclass

OTPAUTH = "otpauth://"


@dataclass(frozen=True)
class Field:
    key: str
    value: str
    line: int  # index into Entry.lines


def _text(raw: bytes) -> str:
    text = raw.decode("utf-8", "surrogateescape")
    if text.endswith("\n"):
        text = text[:-1]
    if text.endswith("\r"):
        text = text[:-1]
    return text


class Entry:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        # Split on LF only: bytes.splitlines() would also split on a lone CR.
        self.lines: list[bytes] = [line + b"\n" for line in raw.split(b"\n")]
        self.lines[-1] = self.lines[-1][:-1]
        if not self.lines[-1]:
            self.lines.pop()
        self.fields: list[Field] = []
        self.otpauth: str | None = None

        for i, line in enumerate(self.lines):
            text = _text(line)
            if text.startswith(OTPAUTH):
                if self.otpauth is None:
                    self.otpauth = text
                continue
            if i == 0 or ":" not in text:
                continue
            key, _, value = text.partition(":")
            key = key.rstrip(" ")
            if not key:
                continue
            if value.startswith(" "):
                value = value[1:]
            self.fields.append(Field(key, value, i))

    @property
    def password(self) -> str:
        """Line 1. In a TOTP-only entry this is the otpauth URI itself."""
        return _text(self.lines[0]) if self.lines else ""

    def get(self, key: str) -> str | None:
        """First value for `key`, matched case-insensitively."""
        key = key.lower()
        for f in self.fields:
            if f.key.lower() == key:
                return f.value
        return None

    def get_all(self, key: str) -> list[Field]:
        key = key.lower()
        return [f for f in self.fields if f.key.lower() == key]

    @property
    def username(self) -> str | None:
        value = self.get("username")
        return value if value is not None else self.get("login")

    @property
    def url(self) -> str | None:
        return self.get("url")

    @property
    def recovery(self) -> list[Field]:
        return self.get_all("recovery")

    def without_line(self, index: int) -> bytes:
        """The entry's bytes with line `index` removed and nothing else changed."""
        if not 0 <= index < len(self.lines):
            raise IndexError(index)
        return b"".join(self.lines[:index] + self.lines[index + 1 :])


SECRET_KEYS = frozenset({"recovery", "password", "pin", "secret", "otp", "totp"})


def public_fields(entry: Entry) -> list[Field]:
    """Fields safe to show in the launcher: line 1, recovery and otpauth stay out."""
    return [f for f in entry.fields if f.key.lower() not in SECRET_KEYS]
