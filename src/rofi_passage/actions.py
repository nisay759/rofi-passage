"""User flows: the entry menu, the action menu and every action."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from urllib.parse import urlsplit

from . import clipboard, launcher, mru, notify, store, tools, totp, typer
from .config import Config
from .entry import Entry, public_fields
from .errors import RofiPassageError
from .launcher import Launcher
from .passage import Passage


@dataclass
class App:
    config: Config
    root: Path
    passage: Passage
    _entries: dict[str, Entry] = field(default_factory=dict)

    @cached_property
    def launcher(self) -> Launcher:
        # Detected on first use: `--entry X --action Y` never opens a menu.
        return launcher.detect(self.config.launcher)

    @cached_property
    def clipboard(self) -> clipboard.Clipboard:
        return clipboard.detect()

    @cached_property
    def typer(self) -> typer.Typer:
        return typer.detect(self.config.typing_tool)

    def read(self, name: str) -> Entry:
        """Decrypt once per run; kept in memory only until the process exits."""
        if name not in self._entries:
            self._entries[name] = Entry(self.passage.show(name))
        return self._entries[name]

    def copy(self, value: str, what: str, name: str) -> None:
        timeout = self.config.clipboard_timeout
        clipboard.copy_with_timeout(self.clipboard, value.encode(), timeout)
        notify.send(f"{what} copied, clears in {timeout} s", store.display_name(name))


# --- entry actions -----------------------------------------------------------


def _password(entry: Entry, name: str) -> str:
    pw = entry.password
    if not pw or pw.startswith("otpauth://"):
        raise RofiPassageError(f"{store.display_name(name)} has no password")
    return pw


def _totp(entry: Entry, name: str) -> totp.Totp:
    if entry.otpauth is None:
        raise RofiPassageError(f"{store.display_name(name)} has no otpauth:// line")
    return totp.parse(entry.otpauth)


def _username(entry: Entry, name: str) -> str:
    user = entry.username
    if not user:
        raise RofiPassageError(f"{store.display_name(name)} has no username")
    return user


def copy_password(app: App, name: str) -> None:
    app.copy(_password(app.read(name), name), "Password", name)


def copy_username(app: App, name: str) -> None:
    app.copy(_username(app.read(name), name), "Username", name)


def copy_totp(app: App, name: str) -> None:
    code = totp.fresh_code(_totp(app.read(name), name))
    app.copy(code, "TOTP code", name)


def _type(app: App, name: str, spec: str) -> None:
    entry = app.read(name)
    steps = typer.parse_sequence(spec)
    wanted = {s.value for s in steps if s.kind == "field"}
    values: dict[str, str] = {}
    if "username" in wanted:
        values["username"] = _username(entry, name)
    if "password" in wanted:
        values["password"] = _password(entry, name)
    if "otp" in wanted:
        values["otp"] = totp.fresh_code(_totp(entry, name))
    tool = app.typer
    typer.perform(tool, steps, values, app.config.type_delay_ms, tools.ui_closed_at())


def autotype(app: App, name: str) -> None:
    entry = app.read(name)
    _type(app, name, entry.get("autotype") or app.config.autotype)


def type_password(app: App, name: str) -> None:
    _type(app, name, "password")


def type_totp(app: App, name: str) -> None:
    _type(app, name, "otp")


def open_url(app: App, name: str) -> None:
    url = app.read(name).url
    if not url:
        raise RofiPassageError(f"{store.display_name(name)} has no url")
    url = url.strip()
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("https", "http") or not parts.netloc:
        raise RofiPassageError("Only https:// and http:// URLs are opened")
    try:
        subprocess.Popen(
            ["xdg-open", url],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as e:
        raise RofiPassageError(f"Cannot run xdg-open: {e.strerror}") from e


def _mask(code: str) -> str:
    tail = code.replace(" ", "")[-4:]
    return f"… {tail}" if tail else "…"


def recovery(app: App, name: str) -> None:
    entry = app.read(name)
    codes = entry.recovery
    if not codes:
        raise RofiPassageError(f"{store.display_name(name)} has no recovery codes")
    rows = [f"recovery {i} ({_mask(f.value)})" for i, f in enumerate(codes, 1)]
    keys = {"remove": "Alt+r"} if app.launcher.supports_keys else {}
    choice = app.launcher.choose(
        "recovery",
        rows,
        keys=keys,
        message="Enter: copy · Alt+r: copy and remove" if keys else None,
    )
    assert choice.index is not None
    selected = codes[choice.index]
    remove = choice.key == "remove"
    if not keys:
        then = app.launcher.choose("code", ["Copy", "Copy and remove"])
        remove = then.index == 1
    app.copy(selected.value, "Recovery code", name)
    if remove:
        remove_line(app, name, selected.line)
        notify.send("Recovery code removed", store.display_name(name))


def remove_line(app: App, name: str, line: int) -> None:
    """REC-2 / SEC-11: rewrite without one line, verify, roll back on any difference."""
    entry = app.read(name)
    expected = entry.without_line(line)
    app.passage.insert(name, expected)
    app._entries.pop(name, None)
    try:
        actual = app.passage.show(name)
    except RofiPassageError:
        actual = None
    if actual != expected:
        app.passage.insert(name, entry.raw)
        raise RofiPassageError(
            f"{store.display_name(name)} did not read back as expected; original restored"
        )


def show_fields(app: App, name: str) -> None:
    entry = app.read(name)
    rows: list[str] = []
    handlers: list[Callable[[], None]] = []

    def add(row: str, handler: Callable[[], None]) -> None:
        rows.append(row)
        handlers.append(handler)

    if entry.password and not entry.password.startswith("otpauth://"):
        add("password: ********", lambda: copy_password(app, name))

    def copier(key: str, value: str) -> Callable[[], None]:
        return lambda: app.copy(value, key, name)

    for f in public_fields(entry):
        add(f"{f.key}: {f.value}", copier(f.key, f.value))
    if entry.recovery:
        add(f"recovery: {len(entry.recovery)} codes", lambda: recovery(app, name))
    if entry.otpauth:
        add("otpauth: ********", lambda: copy_totp(app, name))
    if not rows:
        raise RofiPassageError(f"{store.display_name(name)} has no fields")
    choice = app.launcher.choose(store.display_name(name), rows)
    assert choice.index is not None
    handlers[choice.index]()


def not_yet(label: str) -> Callable[[App, str | None], None]:
    def run(app: App, name: str | None) -> None:
        raise RofiPassageError(f"{label} is not implemented yet")

    return run


# --- registry and menus ------------------------------------------------------


@dataclass(frozen=True)
class Action:
    id: str
    label: str
    run: Callable[[App, str], None] | None = None  # needs an entry
    run_global: Callable[[App, str | None], None] | None = None  # no entry needed


ACTIONS: dict[str, Action] = {
    a.id: a
    for a in [
        Action("autotype", "Autotype", autotype),
        Action("copy-password", "Copy password", copy_password),
        Action("copy-username", "Copy username", copy_username),
        Action("copy-totp", "Copy TOTP code", copy_totp),
        Action("type-password", "Type password", type_password),
        Action("type-totp", "Type TOTP code", type_totp),
        Action("open-url", "Open URL", open_url),
        Action("recovery", "Recovery codes", recovery),
        Action("show-fields", "Show fields", show_fields),
        Action("generate", "Generate new password", not_yet("Generate new password")),
        Action("new", "New entry", run_global=not_yet("New entry")),
        Action("sync", "Sync", run_global=not_yet("Sync")),
    ]
}

CLI_ACTIONS = (
    "autotype", "copy-password", "copy-username", "copy-totp",
    "type-password", "type-totp", "open-url", "new", "sync",
)  # fmt: skip


def _key_bindings(config: Config) -> dict[str, str]:
    """Launcher key name → binding, e.g. {"copy-password": "Alt+1", "action-menu": "Alt+m"}."""
    return {k.replace("_", "-"): v for k, v in config.keys.items() if v}


def action_menu(app: App, name: str | None) -> Action:
    default = app.config.default_action
    ordered = sorted(ACTIONS.values(), key=lambda a: a.id != default)
    if name is None:
        ordered = [a for a in ordered if a.run_global]
    choice = app.launcher.choose("action", [a.label for a in ordered])
    assert choice.index is not None
    return ordered[choice.index]


def entry_menu(app: App, names: list[str], ask_action: bool = True) -> tuple[str, Action | None]:
    """Pick an entry; returns it and the action chosen by key, if any."""
    if not names:
        raise RofiPassageError(
            f"No entries in {app.root} (set `store` in config.toml or PASSAGE_DIR)"
        )
    keys = _key_bindings(app.config) if app.launcher.supports_keys else {}
    choice = app.launcher.choose("passage", names, keys=keys)
    assert choice.index is not None
    name = names[choice.index]
    if choice.key == "action-menu":
        return name, action_menu(app, name)
    if choice.key:
        return name, ACTIONS[choice.key]
    if ask_action and not app.launcher.supports_keys:
        # No custom keys: Enter opens the action menu, default action first.
        return name, action_menu(app, name)
    return name, None


def run(app: App, action_id: str | None = None, name: str | None = None) -> None:
    action = ACTIONS[action_id] if action_id else None
    if action and action.run_global:
        action.run_global(app, name)
        return

    if name is None:
        names = mru.order(store.list_entries(app.root))
        name, picked = entry_menu(app, names, ask_action=action is None)
        action = action or picked
    else:
        store.check_name(name)
        path = app.root / (name + store.SUFFIX)
        if path.is_symlink() or not path.is_file():
            raise RofiPassageError(f"No entry named {store.display_name(name)}")

    if action is None:
        action = ACTIONS.get(app.config.default_action)
        if action is None:
            raise RofiPassageError(f"Unknown default_action: {app.config.default_action}")

    if action.run_global:
        action.run_global(app, name)
        return
    assert action.run is not None
    mru.record(name)
    action.run(app, name)
