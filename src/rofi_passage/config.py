"""Configuration: ~/.config/rofi-passage/config.toml, parsed as TOML only (SEC-10)."""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass, field, fields
from importlib import resources
from pathlib import Path
from typing import Any

from .errors import RofiPassageError

LAUNCHERS = ("auto", "rofi", "fuzzel", "wofi", "bemenu")
TYPING_TOOLS = ("auto", "wtype", "ydotool", "xdotool")


def _default_keys() -> dict[str, str]:
    return {
        "copy_password": "Alt+1",
        "copy_username": "Alt+2",
        "copy_totp": "Alt+3",
        "type_password": "Alt+4",
        "type_totp": "Alt+5",
        "open_url": "Alt+u",
        "new": "Alt+n",
        "sync": "Alt+s",
        "action_menu": "Alt+m",
    }


@dataclass
class Config:
    store: str = ""
    launcher: str = "auto"
    typing_tool: str = "auto"
    clipboard_timeout: int = 45
    default_action: str = "autotype"
    autotype: str = "username :tab password :enter"
    type_delay_ms: int = 100
    password_length: int = 25
    use_agent: bool = True
    pinentry: str = "pinentry"
    keys: dict[str, str] = field(default_factory=_default_keys)

    def store_path(self) -> Path:
        """`store` from the config, then $PASSAGE_DIR, then ~/.passage/store."""
        raw = self.store or os.environ.get("PASSAGE_DIR") or "~/.passage/store"
        return Path(raw).expanduser()


def config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "rofi-passage" / "config.toml"


def sample() -> str:
    """The commented sample config shipped with the package (all defaults)."""
    return resources.files(__package__).joinpath("config.example.toml").read_text("utf-8")


def ensure_exists(path: Path | None = None) -> bool:
    """Write the sample config if no config file exists yet. True when written.

    The sample only holds defaults, so writing it never changes behaviour; a
    failure to write is reported but never stops a run.
    """
    path = path or config_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # O_EXCL: never overwrite a file, even one created a moment ago.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    except FileExistsError:
        return False
    except OSError as e:
        print(f"rofi-passage: cannot create {path}: {e.strerror}", file=sys.stderr)
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(sample())
    return True


def load(path: Path | None = None) -> Config:
    path = path or config_path()
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        return Config()
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise RofiPassageError(f"Cannot read {path}: {e}") from e
    return from_dict(data, source=str(path))


def from_dict(data: dict[str, Any], source: str = "config") -> Config:
    cfg = Config()
    known = {f.name: f for f in fields(Config)}
    for key, value in data.items():
        if key not in known:
            print(f"rofi-passage: {source}: unknown key {key!r} ignored", file=sys.stderr)
            continue
        if key == "keys":
            if not isinstance(value, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in value.items()
            ):
                raise RofiPassageError(f"{source}: [keys] must map names to strings")
            for k in value:
                if k not in cfg.keys:
                    print(f"rofi-passage: {source}: unknown key binding {k!r}", file=sys.stderr)
            cfg.keys.update(value)
            continue
        expected = type(getattr(cfg, key))
        # bool is a subclass of int: reject `clipboard_timeout = true`.
        if type(value) is not expected:
            raise RofiPassageError(
                f"{source}: {key} must be {expected.__name__}, not {type(value).__name__}"
            )
        setattr(cfg, key, value)

    if cfg.launcher not in LAUNCHERS:
        raise RofiPassageError(f"{source}: launcher must be one of {', '.join(LAUNCHERS)}")
    if cfg.typing_tool not in TYPING_TOOLS:
        raise RofiPassageError(f"{source}: typing_tool must be one of {', '.join(TYPING_TOOLS)}")
    for name in ("clipboard_timeout", "password_length"):
        if getattr(cfg, name) <= 0:
            raise RofiPassageError(f"{source}: {name} must be positive")
    if cfg.type_delay_ms < 0:
        raise RofiPassageError(f"{source}: type_delay_ms must not be negative")
    return cfg
