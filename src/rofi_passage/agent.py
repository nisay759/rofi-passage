"""Unlocking, with or without age-agent (UNL-1 to UNL-5, DEC-2, DEC-3).

Per-run mode decrypts the identities file once per run: the passphrase comes
from pinentry, `age -d` reads it from a private pseudo-terminal, and the
decrypted identity is kept in a sealed memfd that passage reads as
`/dev/fd/N`. Nothing touches disk, argv or the environment except that path.
"""

from __future__ import annotations

import contextlib
import ctypes
import enum
import fcntl
import json
import os
import pty
import select
import subprocess
import termios
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from . import tools
from .errors import Cancelled, RofiPassageError

AGE_HEADER = b"age-encryption.org/v1\n"
AGE_ARMOR = b"-----BEGIN AGE ENCRYPTED FILE-----"
PROMPT_TIMEOUT = 60
ATTEMPTS = 3
MAX_IDENTITY = 1 << 20


class Mode(enum.Enum):
    AGENT = "age-agent"
    PER_RUN = "per-run"
    PLAINTEXT = "plaintext"
    PLUGIN = "plugin"


@dataclass
class Detection:
    mode: Mode
    identities: Path
    agent_status: dict[str, Any] = field(default_factory=dict)


def identities_path() -> Path:
    raw = os.environ.get("PASSAGE_IDENTITIES_FILE") or "~/.passage/identities"
    return Path(raw).expanduser()


def _run_agent(*args: str, timeout: float | None = 10) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["age-agent", *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def agent_status() -> tuple[int, dict[str, Any]] | None:
    """(exit code, parsed JSON) of `age-agent status --json`, or None if unusable."""
    if tools.which("age-agent") is None:
        return None
    try:
        proc = _run_agent("status", "--json")
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode not in (0, 1):
        return None
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        data = {}
    return proc.returncode, data if isinstance(data, dict) else {}


def is_locked(code: int, data: dict[str, Any]) -> bool:
    """Read the lock state from the status JSON, falling back to the exit code."""
    if isinstance(data.get("locked"), bool):
        return bool(data["locked"])
    if isinstance(data.get("unlocked"), bool):
        return not data["unlocked"]
    state = data.get("state")
    if isinstance(state, str):
        return state.lower() == "locked"
    return code == 1


def classify(content: bytes | bytearray) -> Mode | None:
    """Mode implied by an identities file's content, without agent mode."""
    if content.startswith(AGE_HEADER) or content.lstrip().startswith(AGE_ARMOR):
        return Mode.PER_RUN
    lines = [line.strip() for line in content.splitlines()]
    if any(line.startswith(b"AGE-SECRET-KEY-") for line in lines):
        return Mode.PLAINTEXT
    if any(line.startswith(b"AGE-PLUGIN-") for line in lines):
        return Mode.PLUGIN
    return None


def detect(use_agent: bool = True) -> Detection:
    """UNL-1: agent first, then the identities file's content."""
    path = identities_path()
    if use_agent:
        status = agent_status()
        if status is not None:
            return Detection(Mode.AGENT, path, status[1])
    try:
        with path.open("rb") as f:
            content = f.read(MAX_IDENTITY)
    except OSError as e:
        raise RofiPassageError(f"Cannot read identities file {path}: {e.strerror}") from e
    mode = classify(content)
    del content
    if mode is None:
        raise RofiPassageError(f"No age identity found in {path}")
    return Detection(mode, path)


# --- pinentry -----------------------------------------------------------------

# Graphical pinentries, tried in order when the config keeps the default
# "pinentry": that name often resolves to pinentry-curses, which needs a
# terminal a hotkey launch does not have (SEC-7). pinentry-gnome3 is only tried
# under GNOME: elsewhere it has no prompter to talk to and falls back to curses.
GRAPHICAL_PINENTRIES = (
    "pinentry-gnome3",
    "pinentry-qt",
    "pinentry-qt5",
    "pinentry-gtk-2",
    "pinentry-gtk",
    "pinentry-fltk",
    "pinentry-x11",
)

# Tried before GRAPHICAL_PINENTRIES, so the prompt looks like the menu it
# follows. fuzzel and wofi have none known to speak enough Assuan for UNL-4.
LAUNCHER_PINENTRIES = {
    "rofi": "pinentry-rofi",
    "bemenu": "pinentry-bemenu",
}


def pick_pinentry(configured: str = "pinentry", launcher: str | None = None) -> str:
    """The configured pinentry, or when left at the default the one matching the
    launcher, else the first graphical one."""
    if configured != "pinentry":
        return configured
    own = LAUNCHER_PINENTRIES.get(launcher or "")
    if own and tools.which(own):
        return own
    gnome = "GNOME" in os.environ.get("XDG_CURRENT_DESKTOP", "").upper().split(":")
    for name in GRAPHICAL_PINENTRIES:
        if name == "pinentry-gnome3" and not gnome:
            continue
        if tools.which(name):
            return name
    return configured


def _assuan_escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


# libgpg-error codes, as the low 16 bits of an Assuan `ERR <code>` line.
GPG_ERR_TIMEOUT = 62
GPG_ERR_CANCELED = 99
GPG_ERR_ASS_UNKNOWN_CMD = 275
GPG_ERR_ASS_CANCELED = 277
GPG_ERR_ENOTTY = 32870
GPG_ERR_ENODEV = 32855


class UnknownCommand(RofiPassageError):
    """The pinentry does not implement an optional command (e.g. SETTIMEOUT)."""


def _unhex(c: int) -> int:
    return int(chr(c), 16)


class Pinentry:
    """Minimal Assuan client for pinentry. The PIN is returned as a bytearray."""

    def __init__(self, command: str = "pinentry") -> None:
        self.command = command
        try:
            self.proc = subprocess.Popen(
                [command],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=0,
            )
        except OSError as e:
            raise RofiPassageError(f"Cannot run {command}: {e.strerror}") from e
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self._in: IO[bytes] = self.proc.stdin
        self._out = self.proc.stdout.fileno()
        self._buf = bytearray()
        self._expect_ok()

    def _readline(self, deadline: float) -> bytearray:
        while b"\n" not in self._buf:
            left = deadline - time.monotonic()
            if left <= 0:
                raise Cancelled("Passphrase prompt timed out")
            ready, _, _ = select.select([self._out], [], [], left)
            if not ready:
                continue
            chunk = bytearray(4096)
            n = os.readv(self._out, [chunk])
            if n == 0:
                raise RofiPassageError("pinentry exited unexpectedly")
            self._buf += chunk[:n]
            chunk[:] = bytes(len(chunk))
        i = self._buf.index(b"\n")
        line = self._buf[:i]
        self._buf[: i + 1] = bytes(i + 1)  # wipe before dropping
        del self._buf[: i + 1]
        return line

    def _transact(self, command: str, timeout: float = 10) -> bytearray | None:
        """Send one command; return the decoded data of `D` lines, or None."""
        self._in.write(command.encode() + b"\n")
        return self._expect_ok(timeout)

    def _expect_ok(self, timeout: float = 10) -> bytearray | None:
        deadline = time.monotonic() + timeout
        data: bytearray | None = None
        while True:
            line = self._readline(deadline)
            if line.startswith(b"OK"):
                return data
            if line.startswith(b"D "):
                data = self._decode(line[2:])
            elif line.startswith(b"ERR"):
                text = line.decode(errors="replace")
                line[:] = bytes(len(line))
                raise self._error(text)
            line[:] = bytes(len(line))  # comments, status lines

    def _error(self, text: str) -> RofiPassageError:
        """Map an `ERR <code> <description>` line to an exception, by code.

        Match on the code, not the text: pinentry-rofi answers SETTIMEOUT with
        `ERR 275 Unknown command "SETTIMEOUT 60"`, which is not a timeout.
        """
        parts = text.split(maxsplit=2)
        try:
            code = int(parts[1]) & 0xFFFF
        except (IndexError, ValueError):
            code = -1
        if code == GPG_ERR_TIMEOUT:
            return Cancelled("Passphrase prompt timed out")
        if code in (GPG_ERR_CANCELED, GPG_ERR_ASS_CANCELED):
            return Cancelled("Unlock cancelled")
        if code == GPG_ERR_ASS_UNKNOWN_CMD:
            return UnknownCommand(f"{self.command}: {text[:80]}")
        if code in (GPG_ERR_ENOTTY, GPG_ERR_ENODEV):
            # A terminal pinentry (curses, tty) started without a terminal.
            return RofiPassageError(
                f"{self.command} needs a terminal; set pinentry = "
                '"pinentry-rofi" (or another graphical pinentry) in config.toml'
            )
        return RofiPassageError(f"{self.command}: {text[:80]}")

    @staticmethod
    def _decode(raw: bytearray) -> bytearray:
        out = bytearray()
        i = 0
        while i < len(raw):
            if raw[i] == 0x25 and i + 2 < len(raw):
                out.append(_unhex(raw[i + 1]) * 16 + _unhex(raw[i + 2]))
                i += 3
            else:
                out.append(raw[i])
                i += 1
        raw[:] = bytes(len(raw))
        return out

    def getpin(self, description: str, error: str | None = None) -> bytearray:
        self._transact("SETTITLE rofi-passage")
        self._transact(f"SETDESC {_assuan_escape(description)}")
        self._transact("SETPROMPT Passphrase:")
        if error:
            self._transact(f"SETERROR {_assuan_escape(error)}")
        # Optional, and sent last: pinentry-rofi does not implement it, and
        # after any error it stops acknowledging commands until GETPIN.
        # Without it, our own deadline on GETPIN still enforces the timeout.
        with contextlib.suppress(UnknownCommand):
            self._transact(f"SETTIMEOUT {PROMPT_TIMEOUT}")
        try:
            pin = self._transact("GETPIN", timeout=PROMPT_TIMEOUT + 5)
        finally:
            tools.mark_ui_closed()
        if not pin:
            raise Cancelled("Empty passphrase")
        return pin

    def close(self) -> None:
        try:
            self._in.write(b"BYE\n")
            self._in.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()  # reap it: no defunct process until we exit
        self._buf[:] = bytes(len(self._buf))


# --- per-run decryption -------------------------------------------------------


class WrongPassphrase(RofiPassageError):
    pass


def _set_ctty() -> None:
    # Runs in the child after setsid(): make the pty slave (fd 0) our
    # controlling terminal, so age's /dev/tty is the private pty.
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def _drain(fd: int, until: bytes | None, deadline: float) -> bytes:
    """Read pty output until `until` appears, EOF/EIO, or the deadline."""
    seen = b""
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], max(0.0, deadline - time.monotonic()))
        if not ready:
            break
        try:
            chunk = os.read(fd, 1024)
        except OSError:  # EIO: the child closed the slave
            break
        if not chunk:
            break
        seen += chunk
        if until is not None and until in seen.lower():
            break
    return seen


def age_decrypt(identities: Path, passphrase: bytearray, age: str = "age") -> bytearray:
    """Run `age -d` on the identities file, answering its prompt through a pty."""
    master, slave = pty.openpty()
    try:
        proc = subprocess.Popen(
            [age, "-d", "--", str(identities)],
            stdin=slave,
            stdout=subprocess.PIPE,
            stderr=slave,
            start_new_session=True,
            preexec_fn=_set_ctty,
        )
    except OSError as e:
        os.close(master)
        os.close(slave)
        raise RofiPassageError(f"Cannot run {age}: {e.strerror}") from e
    os.close(slave)
    assert proc.stdout is not None
    out = bytearray(MAX_IDENTITY)
    n = 0
    try:
        prompt = _drain(master, b"passphrase", time.monotonic() + 15)
        if b"passphrase" in prompt.lower():
            os.write(master, passphrase + b"\n")
        view = memoryview(out)
        while n < len(out):
            got = os.readv(proc.stdout.fileno(), [view[n:]])
            if not got:
                break
            n += got
        view.release()
        try:
            code = proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise RofiPassageError("age did not finish decrypting the identity") from None
        tail = _drain(master, None, time.monotonic() + 0.5)
        if code != 0:
            out[:] = bytes(len(out))
            if b"incorrect passphrase" in tail.lower():
                raise WrongPassphrase("Wrong passphrase")
            last = tail.decode(errors="replace").strip().splitlines()
            raise RofiPassageError(f"age failed: {last[-1][:120] if last else f'exit {code}'}")
        identity = out[:n]
        out[:] = bytes(len(out))
        return identity
    finally:
        proc.stdout.close()
        os.close(master)
        if proc.poll() is None:
            proc.kill()
            proc.wait()


# Linux ABI values (linux/memfd.h, linux/fcntl.h). Python builds made against an
# old glibc, such as the standalone builds uv installs, can lack os.memfd_create
# and the sealing constants even though the running kernel supports them.
MFD_CLOEXEC = getattr(os, "MFD_CLOEXEC", 0x0001)
MFD_ALLOW_SEALING = getattr(os, "MFD_ALLOW_SEALING", 0x0002)
F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1024 + 9)
F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1024 + 10)
F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)


def memfd_create(name: str, flags: int) -> int:
    """os.memfd_create, or libc's memfd_create through ctypes when Python lacks it."""
    if hasattr(os, "memfd_create"):
        return os.memfd_create(name, flags)
    libc = ctypes.CDLL(None, use_errno=True)
    func = getattr(libc, "memfd_create", None)
    if func is None:
        raise RofiPassageError("memfd_create is unavailable (needs glibc 2.27 or newer)")
    func.argtypes = [ctypes.c_char_p, ctypes.c_uint]
    func.restype = ctypes.c_int
    fd = int(func(name.encode(), flags))
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return fd


def sealed_memfd(data: bytearray) -> int:
    """A memfd holding `data`, sealed against writes and resizing (UNL-3)."""
    fd = memfd_create("rofi-passage-identity", MFD_CLOEXEC | MFD_ALLOW_SEALING)
    try:
        view = memoryview(data)
        written = 0
        while written < len(data):
            written += os.write(fd, view[written:])
        view.release()
        fcntl.fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL)
        os.lseek(fd, 0, os.SEEK_SET)
    except BaseException:
        os.close(fd)
        raise
    return fd


# --- the unlocker used by passage calls --------------------------------------


class Unlocker:
    """Unlocks lazily before the first decryption and owns the per-run memfd."""

    def __init__(
        self,
        detection: Detection,
        pinentry: str = "pinentry",
        age: str = "age",
        launcher: Callable[[], str | None] = lambda: None,
    ) -> None:
        self.detection = detection
        self.pinentry = pinentry
        self.age = age
        # Called only for a per-run unlock: detecting the launcher can spawn it.
        self.launcher = launcher
        self._fd: int | None = None
        self._ready = False

    @property
    def mode(self) -> Mode:
        return self.detection.mode

    def ensure(self) -> None:
        if self._ready:
            return
        if self.mode is Mode.AGENT:
            self._unlock_agent()
        elif self.mode is Mode.PER_RUN:
            self._unlock_per_run()
        self._ready = True

    def _unlock_agent(self) -> None:
        status = agent_status()
        if status is None:
            raise RofiPassageError("age-agent stopped responding")
        if not is_locked(*status):
            return
        # age-agent shows its own pinentry; no terminal is involved.
        try:
            proc = _run_agent("unlock", timeout=PROMPT_TIMEOUT + 30)
        except subprocess.TimeoutExpired as e:
            raise Cancelled("Unlock timed out") from e
        except OSError as e:
            raise RofiPassageError(f"Cannot run age-agent: {e.strerror}") from e
        if proc.returncode != 0:
            raise Cancelled("Unlock cancelled")

    def _unlock_per_run(self) -> None:
        pinentry = Pinentry(pick_pinentry(self.pinentry, self.launcher()))
        try:
            error = None
            for _ in range(ATTEMPTS):
                passphrase = pinentry.getpin(
                    f"Passphrase for the age identity\n{self.detection.identities}", error
                )
                try:
                    identity = age_decrypt(self.detection.identities, passphrase, self.age)
                except WrongPassphrase:
                    error = "Wrong passphrase, try again"
                    continue
                finally:
                    passphrase[:] = bytes(len(passphrase))
                try:
                    if classify(identity) not in (Mode.PLAINTEXT, Mode.PLUGIN):
                        raise RofiPassageError("Decrypted identities file holds no age identity")
                    self._fd = sealed_memfd(identity)
                finally:
                    identity[:] = bytes(len(identity))
                return
            raise RofiPassageError("Wrong passphrase, giving up after 3 attempts")
        finally:
            pinentry.close()

    def env(self) -> tuple[dict[str, str], tuple[int, ...]]:
        """Environment overrides and inherited fds for a passage call."""
        if self._fd is None:
            return {}, ()
        return {"PASSAGE_IDENTITIES_FILE": f"/dev/fd/{self._fd}"}, (self._fd,)

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        self._ready = False

    def __enter__(self) -> Unlocker:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
