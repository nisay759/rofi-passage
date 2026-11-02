"""End-to-end runs against real `age` and `passage`, with fake launcher, clipboard,
typing tool, notifications and pinentry. A watcher samples /proc during every
run and fails if a test secret shows up in any process's argv or environment.

Skipped unless `age`, `age-keygen` and `passage` are on PATH (or `passage` is
named by $ROFI_PASSAGE_TEST_PASSAGE).
"""

from __future__ import annotations

import json
import os
import pty
import select
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from rofi_passage import totp
from rofi_passage.agent import _set_ctty

ROOT = Path(__file__).resolve().parent.parent
FAKES = Path(__file__).resolve().parent / "fakes"
PASSAGE = os.environ.get("ROFI_PASSAGE_TEST_PASSAGE") or shutil.which("passage")

pytestmark = pytest.mark.skipif(
    not (shutil.which("age") and shutil.which("age-keygen") and PASSAGE),
    reason="needs age, age-keygen and passage",
)

PASSWORD = "Zq8-test-password-unique-81723"
PASSPHRASE = "correct horse battery staple 4417"
TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
RECOVERY = ["9911 4407", "9922 5508"]
ENTRY = (
    f"{PASSWORD}\n"
    "username: alice@example.com\n"
    "url: https://www.example.com\n"
    "security question: blue\n"
    f"recovery: {RECOVERY[0]}\n"
    "free text kept \xe9 byte for byte\n"
    f"recovery: {RECOVERY[1]}\n"
    f"otpauth://totp/example.com:alice?secret={TOTP_SECRET}&issuer=example.com\n"
).encode()
SECRETS = [PASSWORD, PASSPHRASE, TOTP_SECRET, *RECOVERY]


class ProcWatcher(threading.Thread):
    """Samples /proc/*/cmdline and /proc/*/environ for test secrets."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.stop = threading.Event()
        self.hits: list[str] = []
        self.samples = 0
        self.needles = [s.encode() for s in SECRETS]

    def run(self) -> None:
        while not self.stop.is_set():
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                for part in ("cmdline", "environ"):
                    try:
                        data = Path(f"/proc/{pid}/{part}").read_bytes()
                    except OSError:
                        continue
                    for needle in self.needles:
                        if needle in data:
                            self.hits.append(f"{pid}/{part}")
            self.samples += 1
            time.sleep(0.002)


@dataclass
class Env:
    tmp: Path
    env: dict[str, str]
    store: Path
    identities: Path
    plain: Path  # the same identity, unencrypted, for setup and checks
    watcher: ProcWatcher

    def path(self, key: str) -> Path:
        return Path(self.env[key])

    def script_rofi(self, *steps: dict[str, object]) -> None:
        self.path("FAKE_ROFI_SCRIPT").write_text(json.dumps(list(steps)))

    def pins(self, *pins: str) -> None:
        self.path("FAKE_PINS").write_text("\n".join(pins))

    def run(self, *args: str, timeout: float = 60) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "rofi_passage", *args],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def passage(
        self, *args: str, data: bytes | None = None, identities: Path | None = None
    ) -> bytes:
        env = dict(self.env)
        env["PASSAGE_IDENTITIES_FILE"] = str(identities or self.identities)
        proc = subprocess.run(
            [str(PASSAGE), *args], input=data or b"", env=env, capture_output=True, check=True
        )
        return proc.stdout

    def clip(self) -> bytes:
        p = self.path("FAKE_CLIP")
        return p.read_bytes() if p.exists() else b""

    def log(self) -> list[dict[str, object]]:
        p = self.path("FAKE_LOG")
        return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []

    def notifications(self) -> list[list[str]]:
        p = self.path("FAKE_NOTIFY")
        return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []

    def typed(self) -> list[dict[str, object]]:
        p = self.path("FAKE_TYPED")
        return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []

    def pin_log(self) -> list[str]:
        p = self.path("FAKE_PIN_LOG")
        return p.read_text().splitlines() if p.exists() else []


def encrypt_with_passphrase(src: Path, dst: Path, passphrase: str) -> None:
    """`age -p`, answering both passphrase prompts through a pty."""
    master, slave = pty.openpty()
    proc = subprocess.Popen(
        ["age", "-p", "-o", str(dst), str(src)],
        stdin=slave,
        stdout=subprocess.DEVNULL,
        stderr=slave,
        start_new_session=True,
        preexec_fn=_set_ctty,
    )
    os.close(slave)
    seen = b""
    answered = 0
    deadline = time.monotonic() + 30
    while answered < 2 and time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 1)
        if not ready:
            continue
        try:
            seen += os.read(master, 1024)
        except OSError:
            break
        if seen.lower().count(b"passphrase") > answered:
            os.write(master, passphrase.encode() + b"\n")
            answered += 1
    assert proc.wait(timeout=30) == 0
    os.close(master)


@pytest.fixture(scope="session")
def keys(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path, str]:
    """A plaintext identity, the same identity passphrase-encrypted, its recipient."""
    d = tmp_path_factory.mktemp("keys")
    plain = d / "plain.txt"
    subprocess.run(["age-keygen", "-o", str(plain)], check=True, capture_output=True)
    recipient = subprocess.run(
        ["age-keygen", "-y", str(plain)], check=True, capture_output=True, text=True
    ).stdout.strip()
    encrypted = d / "encrypted.age"
    encrypt_with_passphrase(plain, encrypted, PASSPHRASE)
    return plain, encrypted, recipient


def make_env(tmp: Path, keys: tuple[Path, Path, str], mode: str) -> Iterator[Env]:
    plain, encrypted, recipient = keys
    home = tmp / "home"
    store = home / ".passage/store"
    store.mkdir(parents=True)
    (store / ".age-recipients").write_text(recipient + "\n")
    bindir = tmp / "bin"
    bindir.mkdir()
    for fake in FAKES.iterdir():
        (bindir / fake.name).symlink_to(fake)
        fake.chmod(0o755)
    identities = home / ".passage/identities"
    shutil.copy(plain if mode == "plaintext" else encrypted, identities)

    passage_dir = str(Path(str(PASSAGE)).parent)
    env = {
        "HOME": str(home),
        "PATH": os.pathsep.join([str(bindir), passage_dir, "/usr/bin", "/bin"]),
        "PYTHONPATH": str(ROOT / "src"),
        "WAYLAND_DISPLAY": "wayland-test",
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "PASSAGE_DIR": str(store),
        "PASSAGE_IDENTITIES_FILE": str(identities),
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
        "LANG": "C.UTF-8",
    }
    for key, name in [
        ("FAKE_LOG", "log.jsonl"),
        ("FAKE_CLIP", "clip"),
        ("FAKE_NOTIFY", "notify.jsonl"),
        ("FAKE_TYPED", "typed.jsonl"),
        ("FAKE_PINS", "pins"),
        ("FAKE_PIN_LOG", "pinlog"),
        ("FAKE_ROFI_SCRIPT", "rofi.json"),
    ]:
        env[key] = str(tmp / name)
    cfg = home / ".config/rofi-passage"
    cfg.mkdir(parents=True)
    # Full path, so a graphical pinentry installed on the machine is never picked.
    (cfg / "config.toml").write_text(
        f'clipboard_timeout = 1\ntype_delay_ms = 0\npinentry = "{bindir / "pinentry"}"\n'
    )

    e = Env(tmp, env, store, identities, plain, ProcWatcher())
    # Seed the store with the plaintext identity: setup is not under test.
    e.passage("git", "init", identities=plain)
    e.passage("insert", "-m", "--", "web/example.com", data=ENTRY, identities=plain)
    e.passage(
        "insert", "-m", "--", "web/other.org/work", data=b"pw2\nlogin: bob\n", identities=plain
    )
    e.watcher.start()
    yield e
    e.watcher.stop.set()
    e.watcher.join()
    assert e.watcher.samples > 0
    assert e.watcher.hits == [], f"secret seen in {sorted(set(e.watcher.hits))}"


@pytest.fixture
def plain_env(tmp_path: Path, keys: tuple[Path, Path, str]) -> Iterator[Env]:
    yield from make_env(tmp_path, keys, "plaintext")


@pytest.fixture
def run_env(tmp_path: Path, keys: tuple[Path, Path, str]) -> Iterator[Env]:
    yield from make_env(tmp_path, keys, "per-run")


def files_containing(root: Path, needle: bytes) -> list[Path]:
    hits = []
    for p in root.rglob("*"):
        if p.is_file() and not p.is_symlink():
            try:
                if needle in p.read_bytes():
                    hits.append(p)
            except OSError:
                pass
    return hits


# --- tests --------------------------------------------------------------------


def test_copy_password_plaintext_mode_and_clear(plain_env: Env) -> None:
    e = plain_env
    e.path("FAKE_CLIP").write_bytes(b"previous text")
    proc = e.run("--entry", "web/example.com", "--action", "copy-password")
    assert proc.returncode == 0, proc.stderr
    assert e.clip() == PASSWORD.encode()
    copies = [x for x in e.log() if x["tool"] == "wl-copy"]
    assert copies[0]["argv"] == ["--sensitive"]
    assert any("Password copied, clears in 1 s" in n for n in e.notifications()[0])
    assert all(PASSWORD not in json.dumps(n) for n in e.notifications())

    deadline = time.monotonic() + 10
    while e.clip() != b"previous text" and time.monotonic() < deadline:
        time.sleep(0.1)
    assert e.clip() == b"previous text"


def test_clipboard_left_alone_if_user_copied_something_else(plain_env: Env) -> None:
    e = plain_env
    proc = e.run("--entry", "web/example.com", "--action", "copy-password")
    assert proc.returncode == 0, proc.stderr
    e.path("FAKE_CLIP").write_bytes(b"user copied this")
    time.sleep(2.5)
    assert e.clip() == b"user copied this"


def test_per_run_unlock_entry_menu_and_hotkey(run_env: Env) -> None:
    e = run_env
    e.pins(PASSPHRASE)
    # rofi exit code 11 = kb-custom-2 = copy_username (second binding)
    e.script_rofi({"pick": "web/other.org/work", "code": 11})
    proc = e.run()
    assert proc.returncode == 0, proc.stderr
    assert e.clip() == b"bob"
    assert e.pin_log() == ["GETPIN"]
    rofi = next(x for x in e.log() if x["tool"] == "rofi")
    assert rofi["rows"] == ["web/example.com", "web/other.org/work"]
    argv = rofi["argv"]
    assert isinstance(argv, list) and "-no-markup-rows" in argv
    # No decrypted identity anywhere on disk.
    assert files_containing(e.tmp, b"AGE-SECRET-KEY-") == []
    # The MRU cache holds names only, mode 600.
    mru = e.tmp / "home/.cache/rofi-passage/mru"
    assert mru.read_text() == "web/other.org/work\n"
    assert mru.stat().st_mode & 0o777 == 0o600


def test_per_run_wrong_passphrase_retries(run_env: Env) -> None:
    e = run_env
    e.pins("wrong", PASSPHRASE)
    proc = e.run("--entry", "web/example.com", "--action", "copy-username")
    assert proc.returncode == 0, proc.stderr
    assert e.clip() == b"alice@example.com"
    log = e.pin_log()
    assert log[0] == "GETPIN" and log[1].startswith("SETERROR") and log[2] == "GETPIN"


def test_per_run_cancel_has_no_side_effects(run_env: Env) -> None:
    e = run_env
    e.pins("")
    proc = e.run("--entry", "web/example.com", "--action", "copy-password")
    assert proc.returncode == 1
    assert e.clip() == b""
    assert any("Unlock cancelled" in " ".join(n) for n in e.notifications())


@pytest.mark.parametrize("style", ["rofi", "bemenu"])
def test_pinentry_without_settimeout(run_env: Env, style: str) -> None:
    e = run_env
    e.env["FAKE_PINENTRY_STYLE"] = style
    e.pins("wrong", PASSPHRASE)  # the retry checks rofi's sticky not-OK state too
    proc = e.run("--entry", "web/example.com", "--action", "copy-username", timeout=40)
    assert proc.returncode == 0, proc.stderr
    assert e.clip() == b"alice@example.com"
    assert e.pin_log()[0] == "GETPIN" and e.pin_log()[-1] == "GETPIN"
    assert any(line.startswith("SETERROR") for line in e.pin_log())


def test_terminal_pinentry_gets_an_actionable_error(run_env: Env) -> None:
    e = run_env
    e.pins("!no-tty")
    proc = e.run("--entry", "web/example.com", "--action", "copy-password")
    assert proc.returncode == 1
    assert "pinentry needs a terminal" in proc.stderr
    assert "pinentry-rofi" in proc.stderr
    assert e.clip() == b""


def test_copy_totp(plain_env: Env) -> None:
    e = plain_env
    proc = e.run("--entry", "web/example.com", "--action", "copy-totp")
    assert proc.returncode == 0, proc.stderr
    t = totp.parse(f"otpauth://totp/x?secret={TOTP_SECRET}")
    now = time.time()
    assert e.clip().decode() in {t.code(now), t.code(now - 30)}


def test_autotype_default_sequence(plain_env: Env) -> None:
    e = plain_env
    proc = e.run("--entry", "web/example.com", "--action", "autotype")
    assert proc.returncode == 0, proc.stderr
    assert e.typed() == [
        {"tool": "wtype", "argv": ["-"], "text": "alice@example.com"},
        {"tool": "wtype", "argv": ["-k", "Tab"]},
        {"tool": "wtype", "argv": ["-"], "text": PASSWORD},
        {"tool": "wtype", "argv": ["-k", "Return"]},
    ]


def test_autotype_rejects_unknown_token(plain_env: Env) -> None:
    e = plain_env
    e.passage(
        "insert", "-m", "-f", "--", "web/evil.com",
        data=b"pw\nusername: u\nautotype: username $(touch /tmp/pwned) :enter\n",
    )  # fmt: skip
    proc = e.run("--entry", "web/evil.com", "--action", "autotype")
    assert proc.returncode == 1
    assert e.typed() == []
    assert any("Unknown autotype token" in " ".join(n) for n in e.notifications())


def test_recovery_copy_and_remove_one_passphrase(run_env: Env) -> None:
    e = run_env
    e.pins(PASSPHRASE)
    e.script_rofi(
        {"pick": "web/example.com", "code": 18},  # kb-custom-9 = action_menu
        {"pick": "Recovery codes"},
        {"pick": "recovery 2 (… 5508)", "code": 10},  # kb-custom-1 = remove
    )
    proc = e.run()
    assert proc.returncode == 0, proc.stderr
    assert e.clip() == RECOVERY[1].encode()
    assert e.pin_log() == ["GETPIN"]  # one passphrase for read, write and verify

    after = e.passage("show", "--", "web/example.com", identities=e.plain)
    assert after == ENTRY.replace(f"recovery: {RECOVERY[1]}\n".encode(), b"")
    log = subprocess.run(
        ["git", "-C", str(e.store), "log", "--oneline"], capture_output=True, text=True, check=True
    ).stdout
    assert len(log.splitlines()) >= 3  # passage committed the rewrite


def test_recovery_rows_are_masked(plain_env: Env) -> None:
    e = plain_env
    e.script_rofi({"pick": "web/example.com", "code": 18}, {"pick": "Recovery codes"})
    e.run()  # the recovery menu is not scripted, so it cancels
    menus = [x for x in e.log() if x["tool"] == "rofi"]
    assert menus[-1]["rows"] == ["recovery 1 (… 4407)", "recovery 2 (… 5508)"]
    assert e.clip() == b""


def test_markup_and_control_names_are_plain_text(plain_env: Env) -> None:
    e = plain_env
    e.passage("insert", "-m", "--", "web/<b>bold</b>.com", data=b"pw\n")
    e.script_rofi()
    e.run()
    rofi = next(x for x in e.log() if x["tool"] == "rofi")
    assert "web/<b>bold</b>.com" in rofi["rows"]  # type: ignore[operator]
    assert "-no-markup-rows" in rofi["argv"]  # type: ignore[operator]


def test_open_url_refuses_other_schemes(plain_env: Env) -> None:
    e = plain_env
    e.passage("insert", "-m", "--", "web/bad.com", data=b"pw\nurl: javascript:alert(1)\n")
    proc = e.run("--entry", "web/bad.com", "--action", "open-url")
    assert proc.returncode == 1
    assert any("Only https:// and http://" in " ".join(n) for n in e.notifications())


def test_check_reports_mode(run_env: Env) -> None:
    proc = run_env.run("--check")
    assert proc.returncode == 0, proc.stderr
    assert "unlock: per-run" in proc.stdout
    assert "age-agent would cut prompts" in proc.stdout
    assert "launcher: rofi" in proc.stdout
    assert "clipboard: wl-copy" in proc.stdout
