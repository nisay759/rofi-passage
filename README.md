# rofi-passage

A keyboard-driven launcher for a [passage](https://github.com/FiloSottile/passage) store:
press a hotkey, type a few letters of the account, then copy or type its password,
username or TOTP code. Works on X11 and Wayland, with or without [age-agent](https://github.com/nisay759/age-agent).
See [docs/SPEC.md](docs/SPEC.md) for the full design.

## Status

| Milestone | State |
| --- | --- |
| M1: list, copy password and username, unlocking with and without age-agent, X11 and Wayland clipboard | done |
| M2: autotype, TOTP, recovery codes (including "Copy and remove"), typing-tool detection | done |
| M3: new entry, regenerate, sync | not started (the menu shows "not implemented yet"); MRU and `--last` done |
| M4: packaging, compositor setup notes | not started |

## Requirements

Python 3.11+ (standard library only), passage, git, `age` for the per-run unlock, and:

| Need | X11 | Wayland |
| --- | --- | --- |
| Launcher | rofi | rofi 2.0+, fuzzel, wofi, bemenu |
| Clipboard | xclip | wl-clipboard 2.3.0+ |
| Typing | xdotool | wtype, or ydotool (GNOME) |
| Notifications | notify-send | notify-send |

Optional: age-agent, for one passphrase prompt per session instead of one per run.

## Install

1. Install the system tools for your session. For example, on Wayland:

   ```sh
   # Arch
   sudo pacman -S age rofi wl-clipboard wtype libnotify pinentry
   # Debian / Ubuntu
   sudo apt install age rofi wl-clipboard wtype libnotify-bin pinentry-gnome3
   # Fedora
   sudo dnf install age rofi wl-clipboard wtype libnotify pinentry
   ```

   On X11, use `xclip xdotool` in place of `wl-clipboard wtype`. Check that
   `wl-copy --version` reports 2.3.0 or newer: older versions cannot hide passwords from
   clipboard managers.

2. Install passage, if your distribution does not package it:

   ```sh
   git clone https://github.com/FiloSottile/passage
   cd passage && sudo make install
   ```

3. Install rofi-passage itself, with [pipx](https://pipx.pypa.io) or
   [uv](https://docs.astral.sh/uv/):

   ```sh
   cd rofi-passage
   pipx install .        # or: uv tool install .
   ```

   Either puts a `rofi-passage` command in `~/.local/bin`.

4. Check what rofi-passage detected:

   ```sh
   rofi-passage --check
   ```

5. Bind a hotkey in your window manager, for example in sway or i3:

   ```text
   bindsym $mod+p exec rofi-passage
   bindsym $mod+Shift+p exec rofi-passage --action copy-totp
   ```

## Usage

```sh
rofi-passage                         # entry menu; Enter autotypes
rofi-passage --action copy-totp      # pick an entry, copy its TOTP code
rofi-passage --entry web/example.com --action copy-password
rofi-passage --last                  # reuse the last selected entry
rofi-passage --check                 # show detected tools and unlock mode
```

## Development

```sh
uv venv && uv pip install pytest ruff mypy
.venv/bin/pytest            # integration tests need age, age-keygen and passage on PATH
.venv/bin/ruff check src tests && .venv/bin/mypy src tests
```

The integration tests run the real `age` and `passage` against a temporary store with fake
launcher, clipboard, typing, notification and pinentry tools (`tests/fakes/`). A watcher
samples `/proc/*/cmdline` and `/proc/*/environ` during every run and fails on any test
secret. Point `ROFI_PASSAGE_TEST_PASSAGE` at a passage script if it is not on `PATH`.
