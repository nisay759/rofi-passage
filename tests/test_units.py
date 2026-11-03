"""Config, launcher argument/exit-code handling, autotype parsing, agent helpers."""

import fcntl
import os
import subprocess
from pathlib import Path

import pytest

from rofi_passage import agent, config, launcher, tools, typer
from rofi_passage.errors import Cancelled, RofiPassageError
from rofi_passage.passage import Passage

# --- config ---


def test_config_defaults_and_overrides() -> None:
    cfg = config.from_dict({"clipboard_timeout": 10, "keys": {"copy_password": "Alt+p"}})
    assert cfg.clipboard_timeout == 10
    assert cfg.keys["copy_password"] == "Alt+p"
    assert cfg.keys["copy_username"] == "Alt+2"


@pytest.mark.parametrize(
    "data",
    [
        {"clipboard_timeout": "45"},
        {"clipboard_timeout": True},
        {"clipboard_timeout": 0},
        {"launcher": "dmenu"},
        {"use_agent": 1},
        {"keys": {"copy_password": 1}},
    ],
)
def test_config_rejects_bad_values(data: dict[str, object]) -> None:
    with pytest.raises(RofiPassageError):
        config.from_dict(data)


# --- launcher ---


def test_rofi_argv_resets_custom_slots() -> None:
    argv = launcher.Rofi()._argv(
        "p", {"copy-password": "Alt+1", "action-menu": "Alt+m"}, False, None
    )
    assert "-no-custom" in argv and "-no-markup-rows" in argv
    assert argv[argv.index("-kb-custom-1") + 1] == "Alt+1"
    assert argv[argv.index("-kb-custom-2") + 1] == "Alt+m"
    assert argv[argv.index("-kb-custom-3") + 1] == ""
    assert argv[argv.index("-kb-custom-19") + 1] == ""


def test_rofi_parse_exit_codes() -> None:
    r = launcher.Rofi()
    keys = {"copy-password": "Alt+1", "action-menu": "Alt+m"}
    rows = ["a", "b"]
    assert r._parse(0, "1\n", rows, keys, False) == launcher.Choice(1, "b", None)
    assert r._parse(10, "0\n", rows, keys, False) == launcher.Choice(0, "a", "copy-password")
    assert r._parse(11, "0\n", rows, keys, False).key == "action-menu"
    for code, out in ((1, ""), (0, ""), (0, "7\n"), (12, "0\n")):
        with pytest.raises(Cancelled):
            r._parse(code, out, rows, keys, False)


def test_dmenu_parse_maps_text_back() -> None:
    f = launcher.Fuzzel()
    assert f._parse(0, "b\n", ["a", "b"], {}, False) == launcher.Choice(1, "b")
    with pytest.raises(Cancelled):
        f._parse(0, "typed\n", ["a", "b"], {}, False)
    assert f._parse(0, "typed\n", [], {}, True) == launcher.Choice(None, "typed")


def test_wofi_disables_its_cache() -> None:
    argv = launcher.Wofi()._argv("p", {}, False, None)
    assert argv[argv.index("--cache-file") + 1] == "/dev/null"


# --- autotype ---


def test_parse_sequence() -> None:
    steps = typer.parse_sequence("username :tab password :tab otp :delay :enter")
    assert [(s.kind, s.value) for s in steps] == [
        ("field", "username"),
        ("key", "tab"),
        ("field", "password"),
        ("key", "tab"),
        ("field", "otp"),
        ("delay", ""),
        ("key", "enter"),
    ]


@pytest.mark.parametrize("spec", ["username :tab $(rm -rf ~)", "pass", ":esc", ""])
def test_parse_sequence_rejects_unknown(spec: str) -> None:
    with pytest.raises(RofiPassageError):
        typer.parse_sequence(spec)


class Recorder(typer.Typer):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def type_text(self, text: str) -> None:
        self.calls.append(("text", text))

    def key(self, key: str) -> None:
        self.calls.append(("key", key))


def test_perform_checks_fields_before_typing() -> None:
    rec = Recorder()
    steps = typer.parse_sequence("username :tab password")
    with pytest.raises(RofiPassageError, match="password"):
        typer.perform(rec, steps, {"username": "alice"}, 0)
    assert rec.calls == []
    typer.perform(rec, steps, {"username": "alice", "password": "pw"}, 0)
    assert rec.calls == [("text", "alice"), ("key", "tab"), ("text", "pw")]


def test_typer_argv_keeps_text_off_argv() -> None:
    assert typer.Wtype()._text_argv() == ["wtype", "-"]
    assert typer.Xdotool()._text_argv()[-2:] == ["--file", "-"]
    assert typer.Ydotool()._text_argv()[-2:] == ["--file", "-"]


# --- agent helpers ---


@pytest.mark.parametrize(
    ("code", "data", "locked"),
    [
        (0, {"locked": True}, True),
        (0, {"unlocked": True}, False),
        (0, {"state": "Locked"}, True),
        (1, {}, True),
        (0, {}, False),
    ],
)
def test_is_locked(code: int, data: dict[str, object], locked: bool) -> None:
    assert agent.is_locked(code, data) is locked


def test_classify() -> None:
    assert agent.classify(b"age-encryption.org/v1\n-> scrypt ...") is agent.Mode.PER_RUN
    assert agent.classify(b"-----BEGIN AGE ENCRYPTED FILE-----\n") is agent.Mode.PER_RUN
    assert agent.classify(b"# created\nAGE-SECRET-KEY-1XYZ\n") is agent.Mode.PLAINTEXT
    assert agent.classify(b"AGE-PLUGIN-YUBIKEY-1ABC\n") is agent.Mode.PLUGIN
    assert agent.classify(b"garbage") is None


ENCRYPTED = b"age-encryption.org/v1\n-> scrypt ..."
STUB = b"# recipient: age1xyz\nAGE-PLUGIN-AGENT-1ABC\n"


@pytest.fixture
def ids_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An identities file, an empty XDG_CONFIG_HOME, age-agent and its plugin on PATH."""
    monkeypatch.setenv("PASSAGE_IDENTITIES_FILE", str(tmp_path / "identities"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(tools, "which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr(agent, "agent_status", lambda: (1, {"locked": True}))
    return tmp_path


def setup_agent(root: Path, served: Path, stub: bytes = STUB) -> Path:
    """What `age-agent setup <served>` writes."""
    cfg = root / "config/age-agent"
    cfg.mkdir(parents=True)
    (cfg / "config.toml").write_text(f'[[identity]]\nfile = "{served}"\nrefs = ["5d1c"]\n')
    (cfg / "identities.txt").write_bytes(stub)
    return cfg / "identities.txt"


@pytest.mark.parametrize(
    ("content", "mode"),
    [
        (STUB, agent.Mode.AGENT),
        (ENCRYPTED, agent.Mode.PER_RUN),  # age-agent not set up for it
        (b"AGE-SECRET-KEY-1XYZ\n", agent.Mode.PLAINTEXT),
        (b"AGE-PLUGIN-YUBIKEY-1ABC\n", agent.Mode.PLUGIN),
    ],
)
def test_detect_with_age_agent(ids_env: Path, content: bytes, mode: agent.Mode) -> None:
    (ids_env / "identities").write_bytes(content)
    det = agent.detect()
    assert det.mode is mode
    assert det.identities == ids_env / "identities"
    assert det.agent_unused is (mode is agent.Mode.PER_RUN)


def test_detect_finds_the_stub_for_an_encrypted_file(ids_env: Path) -> None:
    # The user's shell exports PASSAGE_IDENTITIES_FILE=<stub>; a hotkey launch does not.
    ids = ids_env / "identities"
    ids.write_bytes(ENCRYPTED)
    stub = setup_agent(ids_env, ids)
    det = agent.detect()
    assert (det.mode, det.identities) == (agent.Mode.AGENT, stub)


def test_detect_ignores_a_stub_serving_another_file(ids_env: Path) -> None:
    ids = ids_env / "identities"
    ids.write_bytes(ENCRYPTED)
    other = ids_env / "other"
    other.write_bytes(ENCRYPTED)
    setup_agent(ids_env, other)
    assert agent.detect().mode is agent.Mode.PER_RUN


def test_detect_without_age_agent(ids_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ids = ids_env / "identities"
    ids.write_bytes(ENCRYPTED)
    setup_agent(ids_env, ids)
    det = agent.detect(use_agent=False)
    assert (det.mode, det.agent_unused) == (agent.Mode.PER_RUN, False)
    monkeypatch.setattr(agent, "agent_status", lambda: None)
    assert agent.detect().mode is agent.Mode.PER_RUN


def test_detect_stub_without_plugin(ids_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (ids_env / "identities").write_bytes(STUB)
    monkeypatch.setattr(tools, "which", lambda n: None if n == "age-plugin-agent" else n)
    with pytest.raises(RofiPassageError, match="age-plugin-agent is not on PATH"):
        agent.detect()


def test_detect_without_identities_file(ids_env: Path) -> None:
    with pytest.raises(RofiPassageError, match="Cannot read identities file"):
        agent.detect()


def test_agent_unlock_payload_escapes_the_passphrase() -> None:
    assert agent._json_string(bytearray(b'a"b\\c\nd\xc3\xa9')) == bytearray(
        b'a\\"b\\\\c\\u000ad\xc3\xa9'
    )


def test_passage_error_shows_ages_error_line() -> None:
    stderr = (
        b"age: error: failed to decrypt identity file: could not read passphrase\n"
        b"age: report unexpected or unhelpful errors at https://filippo.io/age/report\n"
    )
    proc = subprocess.CompletedProcess(["passage"], 1, b"", stderr)
    err = Passage._error(proc, "Cannot decrypt x")
    assert "failed to decrypt identity file" in str(err)
    proc = subprocess.CompletedProcess(["passage"], 1, b"", b"Error: x is not in the store\n")
    assert "not in the store" in str(Passage._error(proc, "Cannot decrypt x"))


def test_pick_pinentry(monkeypatch: pytest.MonkeyPatch) -> None:
    found = {"pinentry-gnome3", "pinentry-gtk-2", "pinentry-qt"}
    monkeypatch.setattr(tools, "which", lambda n: f"/usr/bin/{n}" if n in found else None)
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "sway")
    assert agent.pick_pinentry("pinentry") == "pinentry-qt"  # gnome3 falls back to curses
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "ubuntu:GNOME")
    assert agent.pick_pinentry("pinentry") == "pinentry-gnome3"
    found.discard("pinentry-gnome3")
    assert agent.pick_pinentry("pinentry-tty") == "pinentry-tty"  # explicit choice wins
    found.add("pinentry-rofi")
    assert agent.pick_pinentry("pinentry", "rofi") == "pinentry-rofi"
    assert agent.pick_pinentry("pinentry", "fuzzel") == "pinentry-qt"
    assert agent.pick_pinentry("pinentry", "bemenu") == "pinentry-qt"  # not installed
    assert agent.pick_pinentry("pinentry-gtk-2", "rofi") == "pinentry-gtk-2"
    found.clear()
    assert agent.pick_pinentry("pinentry") == "pinentry"


@pytest.mark.parametrize(
    ("line", "kind", "message"),
    [
        ('ERR 275 Unknown command "SETTIMEOUT 60"', agent.UnknownCommand, "Unknown"),
        ("ERR 83886142 Timeout <Pinentry>", Cancelled, "timed out"),
        ("ERR 83886179 Operation cancelled <Pinentry>", Cancelled, "Unlock cancelled"),
        ("ERR 277 Operation cancelled", Cancelled, "Unlock cancelled"),
        ("ERR 83918950 Inappropriate ioctl for device", RofiPassageError, "needs a terminal"),
        ("ERR 83886081 General error", RofiPassageError, "General error"),
        ("ERR garbage", RofiPassageError, "garbage"),
    ],
)
def test_pinentry_errors_by_code(line: str, kind: type[Exception], message: str) -> None:
    p = agent.Pinentry.__new__(agent.Pinentry)
    p.command = "pinentry-x"
    err = p._error(line)
    assert type(err) is kind
    assert message in str(err)


def test_pinentry_close_reaps_a_hung_pinentry(tmp_path: Path) -> None:
    hung = tmp_path / "pinentry-hung"
    hung.write_text("#!/bin/sh\necho OK\nexec sleep 30\n")  # ignores BYE
    hung.chmod(0o755)
    p = agent.Pinentry(str(hung))
    p.close()
    assert p.proc.returncode is not None


def test_pinentry_decode() -> None:
    raw = bytearray(b"a%25b%0Ac")
    assert agent.Pinentry._decode(raw) == bytearray(b"a%b\nc")
    assert raw == bytearray(len(raw))  # wiped


def test_example_config_matches_defaults() -> None:
    example = Path(__file__).resolve().parent.parent / "docs/config.example.toml"
    assert config.load(example) == config.Config()


def test_ensure_exists_writes_the_sample_once(tmp_path: Path) -> None:
    path = tmp_path / "rofi-passage/config.toml"
    assert config.ensure_exists(path) is True
    assert path.read_text() == config.sample()
    assert config.load(path) == config.Config()
    path.write_text("clipboard_timeout = 10\n")
    assert config.ensure_exists(path) is False
    assert path.read_text() == "clipboard_timeout = 10\n"  # never overwritten


def test_ensure_exists_keeps_a_symlinked_config(tmp_path: Path) -> None:
    real = tmp_path / "dotfiles/config.toml"
    real.parent.mkdir()
    real.write_text("launcher = 'rofi'\n")
    path = tmp_path / "rofi-passage/config.toml"
    path.parent.mkdir()
    path.symlink_to(real)
    assert config.ensure_exists(path) is False
    assert real.read_text() == "launcher = 'rofi'\n"


def test_docs_sample_is_the_packaged_sample() -> None:
    docs = Path(__file__).resolve().parent.parent / "docs/config.example.toml"
    assert docs.read_text() == config.sample()


@pytest.mark.parametrize("missing_os_memfd", [False, True])
def test_sealed_memfd_with_and_without_python_support(
    monkeypatch: pytest.MonkeyPatch, missing_os_memfd: bool
) -> None:
    # Standalone Python builds (uv) can lack os.memfd_create; the ctypes path
    # must give the same sealed file.
    if missing_os_memfd:
        monkeypatch.delattr(os, "memfd_create", raising=False)
    fd = agent.sealed_memfd(bytearray(b"AGE-SECRET-KEY-1TEST\n"))
    try:
        seals = fcntl.fcntl(fd, agent.F_GET_SEALS)
        wanted = agent.F_SEAL_SEAL | agent.F_SEAL_SHRINK | agent.F_SEAL_GROW | agent.F_SEAL_WRITE
        assert seals & wanted == wanted
        with open(f"/dev/fd/{fd}", "rb") as f:
            assert f.read() == b"AGE-SECRET-KEY-1TEST\n"
        with pytest.raises(PermissionError):
            os.write(fd, b"x")
        assert fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
    finally:
        os.close(fd)


@pytest.mark.parametrize(
    ("closed_ago", "expected"),
    [
        (None, 0.3),  # no menu or prompt shown: the full delay
        (0.0, 0.3),  # a menu just closed: the full delay
        (0.1, 0.2),  # time already spent counts towards it
        (0.5, 0.0),  # a passphrase unlock took longer than the delay
    ],
)
def test_remaining_delay(closed_ago: float | None, expected: float) -> None:
    now = 1000.0
    closed_at = None if closed_ago is None else now - closed_ago
    assert typer.remaining_delay(300, closed_at, now) == pytest.approx(expected)


def test_launcher_marks_ui_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 0, stdout="a\n", stderr="")

    monkeypatch.setattr(tools, "_ui_closed_at", None)
    monkeypatch.setattr(subprocess, "run", fake_run)
    assert launcher.Bemenu().choose("p", ["a"]).index == 0
    assert tools.ui_closed_at() is not None
