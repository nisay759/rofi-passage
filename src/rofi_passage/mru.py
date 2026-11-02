"""Most-recently-used entry names (LST-2). Names only, never secrets (SEC-5)."""

from __future__ import annotations

import os
from pathlib import Path

LIMIT = 200


def path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "rofi-passage" / "mru"


def load() -> list[str]:
    try:
        text = path().read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    return [line for line in text.splitlines() if line]


def record(name: str) -> None:
    names = [name] + [n for n in load() if n != name]
    target = path()
    try:
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = target.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(names[:LIMIT]) + "\n")
        os.replace(tmp, target)
    except OSError:
        pass  # the MRU list is a convenience; never fail an action over it


def order(names: list[str]) -> list[str]:
    """`names` with recently used ones first, the rest in their original order."""
    present = set(names)
    recent = [n for n in load() if n in present]
    seen = set(recent)
    return recent + [n for n in names if n not in seen]
