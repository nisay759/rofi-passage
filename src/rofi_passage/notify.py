"""Notifications through notify-send (NTF-1). Never pass a secret here (SEC-9)."""

from __future__ import annotations

import shutil
import subprocess
import sys

APP = "rofi-passage"


def _stderr(summary: str, body: str) -> None:
    print(f"{APP}: {summary}{': ' + body if body else ''}", file=sys.stderr)


def send(summary: str, body: str = "", *, error: bool = False) -> None:
    if error:
        # Errors also go to stderr: without a notification daemon (common on
        # i3), notify-send fails and the error would otherwise be lost.
        _stderr(summary, body)
    if shutil.which("notify-send") is None:
        if not error:
            _stderr(summary, body)
        return
    argv = ["notify-send", "--app-name", APP]
    if error:
        argv += ["--urgency", "critical"]
    argv += ["--", summary]
    if body:
        argv.append(body)
    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        ok = proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        ok = False
    if not ok and not error:
        _stderr(summary, body)


def error(message: str) -> None:
    send(message, error=True)
