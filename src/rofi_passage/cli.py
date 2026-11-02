"""Command line: `rofi-passage [--action A] [--entry NAME | --last] [--check]`."""

from __future__ import annotations

import argparse
import sys
import traceback

from . import __version__, actions, agent, clipboard, config, launcher, mru, notify, tools, typer
from .agent import Mode
from .errors import Cancelled, RofiPassageError
from .passage import Passage


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="rofi-passage", description=__doc__)
    p.add_argument("--action", choices=actions.CLI_ACTIONS, help="skip the action choice")
    who = p.add_mutually_exclusive_group()
    who.add_argument("--entry", metavar="NAME", help="skip the entry menu")
    who.add_argument("--last", action="store_true", help="reuse the last selected entry")
    p.add_argument("--store", metavar="NAME", help="use a named store from the config")
    p.add_argument("--launcher", choices=config.LAUNCHERS, help="override the configured launcher")
    p.add_argument("--check", action="store_true", help="print the detected setup and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def _probe(label: str, fn: object) -> str:
    try:
        result = fn()  # type: ignore[operator]
    except RofiPassageError as e:
        return f"{label}: not available ({e})"
    return f"{label}: {result}"


def check(cfg: config.Config) -> int:
    """UNL-5 and `--check`: print what was detected; never decrypts anything."""
    print(f"rofi-passage {__version__}")
    print(f"session: {tools.session_type() or 'none (no WAYLAND_DISPLAY or DISPLAY)'}")
    print(f"store: {cfg.store_path()}")
    print(_probe("launcher", lambda: launcher.detect(cfg.launcher).name))

    def clip() -> str:
        c = clipboard.detect()
        if isinstance(c, clipboard.WlClipboard) and not c.sensitive_supported:
            return f"{c.name} (older than 2.3.0: clipboard managers may record passwords)"
        return c.name

    print(_probe("clipboard", clip))
    print(_probe("typing", lambda: typer.detect(cfg.typing_tool).name))
    print(f"passage: {tools.which('passage') or 'not found'}")

    warnings: list[str] = []
    try:
        det = agent.detect(cfg.use_agent)
    except RofiPassageError as e:
        print(f"unlock: error ({e})")
        return 1
    if det.mode is Mode.AGENT:
        state = "unknown"
        status = agent.agent_status()
        if status is not None:
            state = "locked" if agent.is_locked(*status) else "unlocked"
        print(f"unlock: age-agent ({state})")
    else:
        print(f"unlock: {det.mode.value} ({det.identities})")
    if det.mode is Mode.PER_RUN:
        print(f"pinentry: {agent.pick_pinentry(cfg.pinentry, _launcher_name(cfg))}")
        warnings.append(
            "installing age-agent would cut prompts from one per run to one per session"
        )
    if det.mode is Mode.PLAINTEXT:
        warnings.append(f"{det.identities} is not encrypted: the key is unprotected at rest")
    for w in warnings:
        print(f"note: {w}")
    return 0


def _launcher_name(cfg: config.Config) -> str | None:
    """The launcher in use, for matching the pinentry; None when there is none."""
    try:
        return launcher.detect(cfg.launcher).name
    except RofiPassageError:
        return None


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        config.ensure_exists()
        cfg = config.load()
        if args.launcher:
            cfg.launcher = args.launcher
        if args.store:
            raise RofiPassageError("Named stores (--store) are not supported yet")
        if args.check:
            return check(cfg)

        name = args.entry
        if args.last:
            recent = mru.load()
            if not recent:
                raise RofiPassageError("No entry used yet")
            name = recent[0]

        detection = agent.detect(cfg.use_agent)
        with agent.Unlocker(
            detection, cfg.pinentry, launcher=lambda: _launcher_name(cfg)
        ) as unlocker:
            app = actions.App(
                config=cfg,
                root=cfg.store_path(),
                passage=Passage(cfg.store_path(), unlocker),
            )
            actions.run(app, args.action, name)
    except Cancelled as e:
        if str(e) != "Cancelled":
            notify.send(str(e))
        return 1
    except RofiPassageError as e:
        notify.error(str(e))
        return 1
    except Exception as e:
        # A bug. The exception's message could quote entry bytes (for example a
        # decoding error), so the notification and stderr get the type and the
        # stack only, never the message (SEC-9).
        notify.error(f"Internal error ({type(e).__name__}); details on stderr")
        print("".join(traceback.format_tb(e.__traceback__)), file=sys.stderr, end="")
        print(type(e).__name__, file=sys.stderr)
        return 70
    return 0


if __name__ == "__main__":
    sys.exit(main())
