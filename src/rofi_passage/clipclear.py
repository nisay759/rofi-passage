"""Detached helper: wait, then clear the clipboard if it still holds our value (CLP-2).

Reads one JSON job on stdin: {tool, timeout, sha256, previous}. It knows only
the hash of the copied value (SEC-6). If the user copied something else in the
meantime, it leaves the clipboard alone.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import time

from . import clipboard, notify


def run(job: dict[str, object]) -> bool:
    """Returns True when the clipboard was cleared or restored."""
    clip = clipboard.by_name(str(job["tool"]))
    timeout = job["timeout"]
    assert isinstance(timeout, int | float)
    time.sleep(timeout)

    current = clip.paste()
    if current is None:
        return False
    digest = hashlib.sha256(current).hexdigest()
    del current
    if not hmac.compare_digest(digest, str(job["sha256"])):
        return False

    previous = job.get("previous")
    if isinstance(previous, str) and previous:
        clip.copy(base64.b64decode(previous), sensitive=False)
    else:
        clip.clear()
    notify.send("Clipboard cleared")
    return True


def main() -> int:
    job = json.loads(sys.stdin.buffer.read())
    run(job)
    return 0


if __name__ == "__main__":
    sys.exit(main())
