"""Store listing and naming rules (LST-1, SEC-3, SEC-4, NEW-1).

Entry names come from a git remote and are untrusted: listing never follows a
symlink, and every name handed to passage has been checked here first.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from .errors import RofiPassageError

IGNORED_DIRS = frozenset({".git", ".extensions"})
SUFFIX = ".age"

# C0 controls, DEL and C1 controls; also the Unicode line/paragraph separators,
# which some launchers render as line breaks.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")


def display_name(name: str) -> str:
    """The text shown in the launcher: control characters stripped (SEC-3)."""
    return _CONTROL.sub("", name)


def list_entries(root: Path) -> list[str]:
    """Entry names under `root`, sorted, without decrypting anything (LST-1).

    Skips `.git/`, `.extensions/`, non-`.age` files (`.age-recipients`,
    `.gitattributes`), symlinked files and symlinked directories, and names that
    contain control characters or would not survive `check_name`.
    """
    names: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = sorted(
            d for d in dirnames if d not in IGNORED_DIRS and not (here / d).is_symlink()
        )
        for fname in filenames:
            if not fname.endswith(SUFFIX) or fname == SUFFIX:
                continue
            path = here / fname
            try:
                if not stat.S_ISREG(path.lstat().st_mode):
                    continue
            except OSError:
                continue
            name = path.relative_to(root).as_posix()[: -len(SUFFIX)]
            if _CONTROL.search(name) or not _name_ok(name):
                continue
            names.append(name)
    names.sort()
    return names


def categories(root: Path) -> list[str]:
    """Existing folders that are categories, not domains (no dot in any part)."""
    found: list[str] = []
    for dirpath, dirnames, _ in os.walk(root, followlinks=False):
        here = Path(dirpath)
        keep = []
        for d in sorted(dirnames):
            if d in IGNORED_DIRS or d.startswith(".") or "." in d or (here / d).is_symlink():
                continue
            if _CONTROL.search(d):
                continue
            keep.append(d)
            found.append((here / d).relative_to(root).as_posix())
        dirnames[:] = keep
    return sorted(found)


def site_of(name: str) -> str | None:
    """The deepest path component containing a dot, as PassPony matches sites."""
    for part in reversed(name.split("/")):
        if "." in part:
            return part
    return None


def _name_ok(name: str) -> bool:
    if not name or name.startswith("/") or name.startswith("-"):
        return False
    parts = name.split("/")
    return all(p and p not in (".", "..") for p in parts)


def check_name(name: str) -> None:
    """Refuse names passage should never see: `..`, absolute, empty parts, controls."""
    if _CONTROL.search(name):
        raise RofiPassageError("Entry name contains control characters")
    if ".." in name.split("/"):
        raise RofiPassageError("Entry name contains '..'")
    if not _name_ok(name):
        raise RofiPassageError("Invalid entry name")


def check_writable(root: Path, name: str) -> Path:
    """Path of `name`'s file, refusing any symlink on the way (SEC-4)."""
    check_name(name)
    path = root
    parts = name.split("/")
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        path = path / (part + SUFFIX if last else part)
        if path.is_symlink():
            raise RofiPassageError(f"Refusing to write through a symlink: {display_name(name)}")
        if not last and path.exists() and not path.is_dir():
            raise RofiPassageError(f"Not a folder: {display_name(name)}")
    return path


def new_entry_name(category: str, domain: str, label: str = "") -> str:
    """Build `<category>/<domain>[/<label>]`, refusing names that break the contract."""
    category = category.strip().strip("/")
    domain = domain.strip().lower()
    label = label.strip()

    if not domain:
        raise RofiPassageError("Domain is empty")
    if "/" in domain or ":" in domain:
        raise RofiPassageError("Domain must be a bare domain, not a URL")
    if domain.startswith("www."):
        raise RofiPassageError("Drop the 'www.' prefix from the domain")
    if "." not in domain or domain.startswith(".") or domain.endswith("."):
        raise RofiPassageError("Domain must look like example.com")
    if label and ("." in label or "/" in label):
        raise RofiPassageError("Label must not contain '.' or '/'")
    for part in category.split("/") if category else []:
        if "." in part:
            raise RofiPassageError("Category must not contain '.'")

    name = "/".join(p for p in (category, domain, label) if p)
    check_name(name)
    return name
