"""Clipboard adapters (CLP-1) and the clear-after-timeout helper (CLP-2, SEC-6).

Values always go through stdin. The helper is a fresh interpreter, not a fork,
so it never inherits the decrypted entry: it receives only a SHA-256 of the
copied value plus the previous clipboard text to restore.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from . import tools
from .errors import RofiPassageError


def _run(argv: list[str], data: bytes | None = None, timeout: float = 10) -> bytes | None:
    """Run a clipboard tool. Returns stdout, or None when it fails.

    wl-copy and xclip fork a server that keeps the selection alive; their output
    goes to /dev/null on copy so we do not wait for that server to exit.
    """
    try:
        if data is None:
            proc = subprocess.run(
                argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, check=False
            )
            return proc.stdout if proc.returncode == 0 else None
        proc = subprocess.run(
            argv,
            input=data,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        return b"" if proc.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


class Clipboard:
    name = ""

    def copy(self, value: bytes, *, sensitive: bool = True) -> None:
        if _run(self._copy_argv(sensitive), value) is None:
            raise RofiPassageError(f"{self.name} failed to copy")

    def paste(self) -> bytes | None:
        """Current text content, or None when the clipboard holds no text."""
        return _run(self._paste_argv())

    def clear(self) -> None:
        _run(self._clear_argv(), b"" if self._clear_reads_stdin else None)

    _clear_reads_stdin = True

    def _copy_argv(self, sensitive: bool) -> list[str]:
        raise NotImplementedError

    def _paste_argv(self) -> list[str]:
        raise NotImplementedError

    def _clear_argv(self) -> list[str]:
        return self._copy_argv(False)


class WlClipboard(Clipboard):
    name = "wl-copy"
    _clear_reads_stdin = False

    def __init__(self, sensitive_supported: bool = True) -> None:
        self.sensitive_supported = sensitive_supported

    def _copy_argv(self, sensitive: bool) -> list[str]:
        # --sensitive marks the offer so clipboard managers such as cliphist skip it.
        if sensitive and self.sensitive_supported:
            return ["wl-copy", "--sensitive"]
        return ["wl-copy"]

    def _paste_argv(self) -> list[str]:
        return ["wl-paste", "--no-newline", "--type", "text"]

    def _clear_argv(self) -> list[str]:
        return ["wl-copy", "--clear"]


class XClip(Clipboard):
    name = "xclip"

    def _copy_argv(self, sensitive: bool) -> list[str]:
        return ["xclip", "-selection", "clipboard", "-in"]

    def _paste_argv(self) -> list[str]:
        return ["xclip", "-selection", "clipboard", "-out", "-target", "UTF8_STRING"]


WL_SENSITIVE_MIN = (2, 3, 0)


def detect() -> Clipboard:
    session = tools.session_type()
    if session == "wayland" and tools.which("wl-copy"):
        version = tools.version_of(["wl-copy", "--version"])
        # Unknown version: try --sensitive; a too-old wl-copy is flagged by --check.
        return WlClipboard(version is None or version >= WL_SENSITIVE_MIN)
    if session == "x11" and tools.which("xclip"):
        return XClip()
    if session == "":
        raise RofiPassageError("No graphical session (neither WAYLAND_DISPLAY nor DISPLAY set)")
    tool = "wl-copy (wl-clipboard)" if session == "wayland" else "xclip"
    raise RofiPassageError(f"Clipboard tool not found: install {tool}")


def by_name(name: str) -> Clipboard:
    if name == "wl-copy":
        return WlClipboard()
    if name == "xclip":
        return XClip()
    raise ValueError(name)


def copy_with_timeout(clip: Clipboard, value: bytes, timeout: int) -> None:
    """Copy `value`, then hand a SHA-256 of it to a detached helper that clears it."""
    previous = clip.paste()
    clip.copy(value)
    job = {
        "tool": clip.name,
        "timeout": timeout,
        "sha256": hashlib.sha256(value).hexdigest(),
        "previous": base64.b64encode(previous).decode() if previous else None,
    }
    spawn_clearer(job)


def spawn_clearer(job: dict[str, object]) -> None:
    src = str(Path(__file__).resolve().parent.parent)
    env = dict(os.environ)
    env["PYTHONPATH"] = src + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    proc = subprocess.Popen(
        [sys.executable, "-m", "rofi_passage.clipclear"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
        env=env,
    )
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(job).encode())
    proc.stdin.close()
