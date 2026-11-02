"""Typing tools (TYP-1) and the autotype sequence (TYP-2).

Text goes through stdin (`wtype -`, `xdotool type --file -`,
`ydotool type --file -`), never argv (SEC-2).
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from typing import ClassVar

from . import tools
from .errors import RofiPassageError

FIELDS = ("username", "password", "otp")
KEYS = ("tab", "enter", "space")
DELAY_TOKEN_MS = 500


@dataclass(frozen=True)
class Step:
    kind: str  # "field", "key" or "delay"
    value: str = ""


def parse_sequence(spec: str) -> list[Step]:
    """Parse an autotype spec; unknown tokens abort, they are never typed."""
    steps: list[Step] = []
    for token in spec.split():
        if token in FIELDS:
            steps.append(Step("field", token))
        elif token.startswith(":") and token[1:] in KEYS:
            steps.append(Step("key", token[1:]))
        elif token == ":delay":  # noqa: S105
            steps.append(Step("delay"))
        else:
            raise RofiPassageError(f"Unknown autotype token: {token[:20]!r}")
    if not steps:
        raise RofiPassageError("Empty autotype sequence")
    return steps


def _run(argv: list[str], data: bytes | None = None) -> None:
    try:
        proc = subprocess.run(
            argv,
            input=data,
            stdin=None if data is not None else subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RofiPassageError(f"{argv[0]} failed: {e}") from e
    if proc.returncode != 0:
        raise RofiPassageError(f"{argv[0]} failed (exit {proc.returncode})")


class Typer:
    name = ""

    def type_text(self, text: str) -> None:
        _run(self._text_argv(), text.encode())

    def key(self, key: str) -> None:
        _run(self._key_argv(key))

    def _text_argv(self) -> list[str]:
        raise NotImplementedError

    def _key_argv(self, key: str) -> list[str]:
        raise NotImplementedError


class Wtype(Typer):
    name = "wtype"
    _names: ClassVar[dict[str, str]] = {"tab": "Tab", "enter": "Return", "space": "space"}

    def _text_argv(self) -> list[str]:
        return ["wtype", "-"]

    def _key_argv(self, key: str) -> list[str]:
        return ["wtype", "-k", self._names[key]]


class Xdotool(Typer):
    name = "xdotool"
    _names: ClassVar[dict[str, str]] = {"tab": "Tab", "enter": "Return", "space": "space"}

    def _text_argv(self) -> list[str]:
        return ["xdotool", "type", "--clearmodifiers", "--file", "-"]

    def _key_argv(self, key: str) -> list[str]:
        return ["xdotool", "key", "--clearmodifiers", self._names[key]]


class Ydotool(Typer):
    name = "ydotool"
    # Key codes from linux/input-event-codes.h
    _codes: ClassVar[dict[str, int]] = {"tab": 15, "enter": 28, "space": 57}

    def _text_argv(self) -> list[str]:
        return ["ydotool", "type", "--file", "-"]

    def _key_argv(self, key: str) -> list[str]:
        code = self._codes[key]
        return ["ydotool", "key", f"{code}:1", f"{code}:0"]


TYPERS: dict[str, type[Typer]] = {"wtype": Wtype, "xdotool": Xdotool, "ydotool": Ydotool}


def detect(preferred: str = "auto") -> Typer:
    if preferred != "auto":
        if tools.which(preferred) is None:
            raise RofiPassageError(f"Typing tool not found: {preferred}")
        return TYPERS[preferred]()
    session = tools.session_type()
    order = ["wtype", "ydotool"] if session == "wayland" else ["xdotool"]
    for name in order:
        if tools.which(name):
            return TYPERS[name]()
    raise RofiPassageError(f"No typing tool found (install {' or '.join(order)})")


def remaining_delay(delay_ms: int, ui_closed_at: float | None, now: float) -> float:
    """Seconds still to wait before the first key.

    The delay lets our last window close and focus return to the target. Time
    already spent since that window closed (decrypting, mostly the passphrase
    unlock) counts towards it. With no window shown, wait the full delay.
    """
    delay = delay_ms / 1000
    if ui_closed_at is None:
        return delay
    return max(0.0, delay - (now - ui_closed_at))


def perform(
    typer: Typer,
    steps: list[Step],
    values: dict[str, str],
    delay_ms: int,
    ui_closed_at: float | None = None,
) -> None:
    """Type `steps`, taking field values from `values`; checks everything first."""
    for step in steps:
        if step.kind == "field" and not values.get(step.value):
            raise RofiPassageError(f"Entry has no {step.value} to type")
    time.sleep(remaining_delay(delay_ms, ui_closed_at, time.monotonic()))
    for step in steps:
        if step.kind == "field":
            typer.type_text(values[step.value])
        elif step.kind == "key":
            typer.key(step.value)
        else:
            time.sleep(DELAY_TOKEN_MS / 1000)
