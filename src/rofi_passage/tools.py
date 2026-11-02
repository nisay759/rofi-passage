"""Small helpers shared by the tool adapters."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time


def session_type() -> str:
    """'wayland', 'x11' or '' when neither display is reachable."""
    if os.environ.get("WAYLAND_DISPLAY"):
        return "wayland"
    if os.environ.get("DISPLAY"):
        return "x11"
    return ""


_ui_closed_at: float | None = None


def mark_ui_closed() -> None:
    """Record that a window of ours (menu, passphrase prompt) just closed."""
    global _ui_closed_at
    _ui_closed_at = time.monotonic()


def ui_closed_at() -> float | None:
    """time.monotonic() when our last window closed, or None if none was shown."""
    return _ui_closed_at


def which(name: str) -> str | None:
    return shutil.which(name)


def version_of(argv: list[str]) -> tuple[int, ...] | None:
    """First dotted version number in a tool's output, e.g. (2, 3, 0)."""
    try:
        out = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", out.stdout + out.stderr)
    if not match:
        return None
    return tuple(int(g) for g in match.groups() if g is not None)
