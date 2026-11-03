"""Unlocking, with or without age-agent (UNL-1 to UNL-5, DEC-2, DEC-3).

Per-run mode decrypts the identities file once per run: the passphrase comes
from pinentry, `age -d` reads it from a private pseudo-terminal, and the
decrypted identity is kept in a sealed memfd that passage reads as
`/dev/fd/N`. Nothing touches disk, argv or the environment except that path.

Agent mode decrypts through age-agent's stub identities file, and unlocks a
locked agent over its socket with a passphrase from our own pinentry: the
`age-agent unlock` command only prompts on a terminal.
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
import socket
import struct
import subprocess
import termios
import time
import tomllib
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
AGENT_STUB = b"AGE-PLUGIN-AGENT-"
AGENT_PROTOCOL = 1
AGENT_MAX_MESSAGE = 64 * 1024


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
    agent_unused: bool = False  # age-agent answers, but is not set up for this file


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
    """(exit code, parsed JSON) of `age-agent status --json`, or None if unusable.
    Exit 0 unlocked, 1 locked, 2 no daemon running."""
    if tools.which("age-agent") is None:
        return None
    try:
        proc = _run_agent("status", "--json")
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode not in (0, 1, 2):
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


def _is_agent_stub(content: bytes) -> bool:
    return any(line.strip().startswith(AGENT_STUB) for line in content.splitlines())


def _agent_config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or "~/.config"
    return Path(base).expanduser() / "age-agent"


def agent_stub_for(identities: Path) -> Path | None:
    """age-agent's stub file, when its config.toml serves `identities`.

    `age-agent setup <file>` writes the stub and asks the user to export
    PASSAGE_IDENTITIES_FILE, which a hotkey launch often does not see, so the
    stub is looked up here instead of trusting the environment."""
    cfg_dir = _agent_config_dir()
    stub = cfg_dir / "identities.txt"
    try:
        with (cfg_dir / "config.toml").open("rb") as f:
            cfg = tomllib.load(f)
        if not _is_agent_stub(stub.read_bytes()):
            return None
    except (OSError, tomllib.TOMLDecodeError):
        return None
    entries = cfg.get("identity")
    for entry in entries if isinstance(entries, list) else []:
        file = entry.get("file") if isinstance(entry, dict) else None
        if not isinstance(file, str):
            continue
        with contextlib.suppress(OSError):
            if os.path.samefile(Path(file).expanduser(), identities):
                return stub
    return None


def detect(use_agent: bool = True) -> Detection:
    """UNL-1: agent mode when age-agent is installed and serves the identities
    file (directly, or through the stub its setup wrote), else the mode
    implied by the file's content."""
    path = identities_path()
    try:
        with path.open("rb") as f:
            content = f.read(MAX_IDENTITY)
    except OSError as e:
        raise RofiPassageError(f"Cannot read identities file {path}: {e.strerror}") from e
    mode = classify(content)
    stub_in_use = _is_agent_stub(content)
    del content
    plugin = tools.which("age-plugin-agent") is not None
    if stub_in_use and not plugin:
        raise RofiPassageError(
            f"{path} holds age-agent stubs but age-plugin-agent is not on PATH; "
            "install it or point PASSAGE_IDENTITIES_FILE back to the encrypted identities file"
        )
    status = agent_status() if use_agent and plugin else None
    if status is not None:
        if stub_in_use:
            return Detection(Mode.AGENT, path, status[1])
        stub = agent_stub_for(path) if mode is Mode.PER_RUN else None
        if stub is not None:
            return Detection(Mode.AGENT, stub, status[1])
    if mode is None:
        raise RofiPassageError(f"No age identity found in {path}")
    return Detection(mode, path, agent_unused=status is not None and mode is Mode.PER_RUN)


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


# --- age-agent socket -------------------------------------------------------


def _json_string(raw: bytearray) -> bytearray:
    """`raw` as the body of a JSON string, built without an immutable copy."""
    out = bytearray()
    for b in raw:
        if b in (0x22, 0x5C):
            out += bytes((0x5C, b))
        elif b < 0x20:
            out += b"\\u%04x" % b
        else:
            out.append(b)
    return out


class AgentError(RofiPassageError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"age-agent: {message}")
        self.code = code


class AgentSocket:
    """Client for age-agent's socket protocol, version 1: each message is a
    4-byte big-endian length and one JSON object."""

    def __init__(self, path: Path) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        try:
            self.sock.connect(str(path))
            creds = self.sock.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            _, uid, _ = struct.unpack("3i", creds)
            if uid != os.getuid():
                raise RofiPassageError(f"{path} is served by another user")
            reply = self.call({"type": "hello", "version": AGENT_PROTOCOL})
            if reply.get("version") != AGENT_PROTOCOL:
                raise RofiPassageError("age-agent speaks an unsupported protocol version")
        except BaseException:
            self.sock.close()
            raise

    @staticmethod
    def path() -> Path:
        runtime = os.environ.get("XDG_RUNTIME_DIR")
        if not runtime:
            raise RofiPassageError("XDG_RUNTIME_DIR is not set; age-agent needs it")
        return Path(runtime) / "age-agent/agent.sock"

    @classmethod
    def connect_or_start(cls) -> AgentSocket:
        path = cls.path()
        try:
            return cls(path)
        except (FileNotFoundError, ConnectionRefusedError):
            pass
        # Waits until the daemon accepts connections, up to 3 s.
        try:
            proc = _run_agent("daemon")
        except (OSError, subprocess.TimeoutExpired) as e:
            raise RofiPassageError(f"Cannot start age-agent: {e}") from e
        if proc.returncode != 0 and "already running" not in proc.stderr:
            raise RofiPassageError(f"Cannot start age-agent: {proc.stderr.strip()[:160]}")
        return cls(path)

    def _send(self, payload: bytearray) -> None:
        frame = bytearray(4 + len(payload))
        frame[:4] = len(payload).to_bytes(4, "big")
        frame[4:] = payload
        try:
            self.sock.sendall(frame)
        finally:
            frame[:] = bytes(len(frame))

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise RofiPassageError("age-agent closed the connection")
            buf += chunk
        return bytes(buf)

    def _reply(self) -> dict[str, Any]:
        n = int.from_bytes(self._recv_exact(4), "big")
        if n > AGENT_MAX_MESSAGE:
            raise RofiPassageError("age-agent sent an oversized message")
        reply = json.loads(self._recv_exact(n))
        if not isinstance(reply, dict):
            raise RofiPassageError("age-agent sent a malformed reply")
        error = reply.get("error")
        if isinstance(error, dict):
            raise AgentError(str(error.get("code")), str(error.get("message")))
        return reply

    def call(self, request: dict[str, Any]) -> dict[str, Any]:
        self._send(bytearray(json.dumps(request).encode()))
        return self._reply()

    def unlock(self, passphrase: bytearray, epoch: int | None) -> None:
        """Raises AgentError with code bad_passphrase, cancelled, no_identities…"""
        body = _json_string(passphrase)
        payload = bytearray(b'{"type":"unlock","passphrase":"') + body + b'"'
        body[:] = bytes(len(body))
        if epoch is not None:
            payload += b',"epoch":%d' % epoch
        payload += b"}"
        try:
            self._send(payload)
        finally:
            payload[:] = bytes(len(payload))
        # Unlocking runs scrypt on the identity file: allow more than a status.
        self.sock.settimeout(60)
        self._reply()

    def close(self) -> None:
        self.sock.close()


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
        # Over the socket with our own pinentry: `age-agent unlock` prompts on
        # a terminal only, and a hotkey launch has none.
        conn = AgentSocket.connect_or_start()
        try:
            status = conn.call({"type": "status"})
            if not status.get("locked"):
                return
            epoch = status.get("epoch") if isinstance(status.get("epoch"), int) else None
            pinentry = Pinentry(pick_pinentry(self.pinentry, self.launcher()))
            try:
                error = None
                for _ in range(ATTEMPTS):
                    passphrase = pinentry.getpin("Passphrase to unlock age-agent", error)
                    try:
                        conn.unlock(passphrase, epoch)
                        return
                    except AgentError as e:
                        if e.code != "bad_passphrase":
                            failure = self._agent_failure(conn, e)
                            if failure is None:
                                return
                            raise failure from e
                        error = "Wrong passphrase, try again"
                    finally:
                        passphrase[:] = bytes(len(passphrase))
                raise RofiPassageError("Wrong passphrase, giving up after 3 attempts")
            finally:
                pinentry.close()
        finally:
            conn.close()

    @staticmethod
    def _agent_failure(conn: AgentSocket, e: AgentError) -> Exception | None:
        """None when the unlock can be ignored, else the error to raise."""
        if e.code == "cancelled":
            # The agent was locked or unlocked while we prompted (LCK-1).
            with contextlib.suppress(RofiPassageError, OSError):
                if not conn.call({"type": "status"}).get("locked"):
                    return None
            return Cancelled("Unlock cancelled by age-agent lock")
        if e.code == "no_identities":
            return RofiPassageError("age-agent has no identities; run `age-agent setup`")
        return e

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
        if self.mode is Mode.AGENT:
            # The stub, which PASSAGE_IDENTITIES_FILE may not name (see detect).
            return {"PASSAGE_IDENTITIES_FILE": str(self.detection.identities)}, ()
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
