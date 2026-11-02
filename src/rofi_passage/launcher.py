"""Launcher adapters: rofi with custom keys, fuzzel/wofi/bemenu in plain dmenu mode.

Rows are plain text: markup is off and control characters are stripped before
they reach the launcher (SEC-3). The launcher never receives a secret (SEC-5).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from . import tools
from .errors import Cancelled, RofiPassageError
from .store import display_name

ROFI_CUSTOM_KEYS = 19  # kb-custom-1..19 exit with 10..28


@dataclass(frozen=True)
class Choice:
    index: int | None  # row index, or None for text typed by the user
    text: str
    key: str | None = None  # name of the custom key pressed; None for Enter


class Launcher:
    name = ""
    supports_keys = False

    def choose(
        self,
        prompt: str,
        rows: list[str],
        *,
        keys: dict[str, str] | None = None,
        allow_custom: bool = False,
        message: str | None = None,
    ) -> Choice:
        rows = [display_name(r) for r in rows]
        argv = self._argv(prompt, keys or {}, allow_custom, message)
        try:
            proc = subprocess.run(
                argv,
                input="\n".join(rows) + ("\n" if rows else ""),
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as e:
            raise RofiPassageError(f"Cannot run {self.name}: {e.strerror}") from e
        tools.mark_ui_closed()
        return self._parse(proc.returncode, proc.stdout, rows, keys or {}, allow_custom)

    def input(self, prompt: str, *, message: str | None = None) -> str:
        """Free text from the user (new-entry fields). Never used for secrets."""
        text = self.choose(prompt, [], allow_custom=True, message=message).text
        return display_name(text).strip()

    def _argv(
        self, prompt: str, keys: dict[str, str], allow_custom: bool, message: str | None
    ) -> list[str]:
        raise NotImplementedError

    def _parse(
        self, code: int, out: str, rows: list[str], keys: dict[str, str], allow_custom: bool
    ) -> Choice:
        text = out.rstrip("\n")
        if code != 0 or not text:
            raise Cancelled()
        return _match(text, rows, allow_custom)


def _match(text: str, rows: list[str], allow_custom: bool) -> Choice:
    try:
        return Choice(rows.index(text), text)
    except ValueError:
        if allow_custom:
            return Choice(None, text)
        raise Cancelled() from None


class Rofi(Launcher):
    name = "rofi"
    supports_keys = True

    def _argv(
        self, prompt: str, keys: dict[str, str], allow_custom: bool, message: str | None
    ) -> list[str]:
        argv = ["rofi", "-dmenu", "-i", "-matching", "fuzzy", "-no-markup-rows", "-p", prompt]
        argv += ["-format", "s" if allow_custom else "i"]
        if not allow_custom:
            argv.append("-no-custom")
        if message:
            argv += ["-mesg", message]
        if len(keys) > ROFI_CUSTOM_KEYS:
            raise RofiPassageError("Too many key bindings for rofi")
        # Reset every custom slot first so our bindings never clash with rofi's
        # defaults (kb-custom-N is Alt+N out of the box).
        bound = list(keys.values())
        for n in range(1, ROFI_CUSTOM_KEYS + 1):
            argv += [f"-kb-custom-{n}", bound[n - 1] if n <= len(bound) else ""]
        return argv

    def _parse(
        self, code: int, out: str, rows: list[str], keys: dict[str, str], allow_custom: bool
    ) -> Choice:
        text = out.rstrip("\n")
        key = None
        if 10 <= code < 10 + ROFI_CUSTOM_KEYS:
            names = list(keys)
            slot = code - 10
            if slot >= len(names):
                raise Cancelled()
            key = names[slot]
        elif code != 0:
            raise Cancelled()
        if not text:
            raise Cancelled()
        if allow_custom:
            choice = _match(text, rows, True)
        else:
            try:
                index = int(text)
            except ValueError:
                raise Cancelled() from None
            if not 0 <= index < len(rows):
                raise Cancelled()
            choice = Choice(index, rows[index])
        return Choice(choice.index, choice.text, key)


class Fuzzel(Launcher):
    name = "fuzzel"

    def _argv(
        self, prompt: str, keys: dict[str, str], allow_custom: bool, message: str | None
    ) -> list[str]:
        argv = ["fuzzel", "--dmenu", "--prompt", f"{prompt}> "]
        if message:
            argv += ["--placeholder", message]
        return argv


class Wofi(Launcher):
    name = "wofi"

    def _argv(
        self, prompt: str, keys: dict[str, str], allow_custom: bool, message: str | None
    ) -> list[str]:
        # wofi's dmenu mode remembers selections in a cache file unless told not to.
        return [
            "wofi", "--dmenu", "--insensitive", "--matching", "fuzzy",
            "--cache-file", "/dev/null", "--prompt", message or prompt,
        ]  # fmt: skip


class Bemenu(Launcher):
    name = "bemenu"

    def _argv(
        self, prompt: str, keys: dict[str, str], allow_custom: bool, message: str | None
    ) -> list[str]:
        return ["bemenu", "-i", "-p", message or prompt]


ADAPTERS: dict[str, type[Launcher]] = {
    "rofi": Rofi,
    "fuzzel": Fuzzel,
    "wofi": Wofi,
    "bemenu": Bemenu,
}


def _rofi_usable(session: str) -> bool:
    if tools.which("rofi") is None:
        return False
    if session != "wayland":
        return True
    version = tools.version_of(["rofi", "-version"])
    return version is not None and version >= (2, 0)


def detect(preferred: str = "auto") -> Launcher:
    if preferred != "auto":
        if preferred not in ADAPTERS:
            raise RofiPassageError(f"Unknown launcher: {preferred}")
        if tools.which(preferred) is None:
            raise RofiPassageError(f"Launcher not found: {preferred}")
        return ADAPTERS[preferred]()

    session = tools.session_type()
    if _rofi_usable(session):
        return Rofi()
    order = ["fuzzel", "wofi", "bemenu"] if session == "wayland" else ["bemenu"]
    for name in order:
        if tools.which(name):
            return ADAPTERS[name]()
    raise RofiPassageError("No launcher found (install rofi, fuzzel, wofi or bemenu)")
