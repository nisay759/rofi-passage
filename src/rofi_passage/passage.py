"""Every read and write goes through FiloSottile's passage (DEC-1).

Names are passed after `--` (SEC-3) and contents through stdin (SEC-2).
Output is kept in memory only.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from . import store
from .agent import Unlocker
from .errors import RofiPassageError


class Passage:
    def __init__(self, root: Path, unlocker: Unlocker, command: str = "passage") -> None:
        self.root = root
        self.unlocker = unlocker
        self.command = command

    def _run(
        self, args: list[str], data: bytes | None = None, *, decrypts: bool = True
    ) -> subprocess.CompletedProcess[bytes]:
        if decrypts:
            self.unlocker.ensure()
        extra, fds = self.unlocker.env() if decrypts else ({}, ())
        env = dict(os.environ)
        env["PASSAGE_DIR"] = str(self.root)
        env.update(extra)
        try:
            return subprocess.run(
                [self.command, *args],
                input=data if data is not None else b"",
                capture_output=True,
                env=env,
                pass_fds=fds,
                timeout=120,
                check=False,
            )
        except FileNotFoundError as e:
            raise RofiPassageError(f"{self.command} not found on PATH") from e
        except subprocess.TimeoutExpired as e:
            raise RofiPassageError(f"{self.command} {args[0]} timed out") from e

    @staticmethod
    def _error(proc: subprocess.CompletedProcess[bytes], what: str) -> RofiPassageError:
        lines = proc.stderr.decode(errors="replace").strip().splitlines()
        reason = lines[-1][:160] if lines else f"exit {proc.returncode}"
        return RofiPassageError(f"{what}: {store.display_name(reason)}")

    def show(self, name: str) -> bytes:
        store.check_name(name)
        proc = self._run(["show", "--", name])
        if proc.returncode != 0:
            raise self._error(proc, f"Cannot decrypt {store.display_name(name)}")
        return proc.stdout

    def insert(self, name: str, content: bytes) -> None:
        """`passage insert -m -f`: content through stdin; passage commits."""
        store.check_writable(self.root, name)
        # passage refuses to start without a readable identity, even to encrypt.
        proc = self._run(["insert", "-m", "-f", "--", name], content)
        if proc.returncode != 0:
            raise self._error(proc, f"Cannot save {store.display_name(name)}")

    def generate_in_place(self, name: str, length: int) -> None:
        store.check_writable(self.root, name)
        proc = self._run(["generate", "-i", "--", name, str(length)])
        if proc.returncode != 0:
            raise self._error(proc, f"Cannot generate a password for {store.display_name(name)}")

    def git(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return self._run(["git", *args], decrypts=False)
