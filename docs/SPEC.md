# rofi-passage — SPEC

## Overview

rofi-passage is a keyboard-driven launcher for a passage store: one hotkey, fuzzy-pick an account, then copy or type its password, username or TOTP code. It plays the role rofi-pass plays for pass, rewritten around the merged entry format, and works with or without age-agent.

**Goals**

- Pick an entry and act on it in three keystrokes or fewer: hotkey, type a few letters, Enter.
- Autotype "username, Tab, password, Enter" from one merged entry.
- Live TOTP codes and recovery codes from the same entry.
- X11 and Wayland, with rofi as the reference launcher and fuzzel, wofi and bemenu as dmenu-compatible fallbacks.
- Never prompt in a terminal: unlock through age-agent when it is installed, through rofi-passage's own pinentry fallback when it is not.
- No code path that executes text found in an entry.

**Non-goals**

- Windows and macOS. The GUI covers them.
- Browser integration and form detection. Autotype types into whatever window has focus.
- Store administration: recipients, re-encryption and git conflicts belong to the passage CLI and the GUI. rofi-passage only runs `passage git pull` and `push` on request.
- Compatibility with rofi-pass's config file or its split-file layouts.

**Depends on**

- FiloSottile's passage, for every read and write. rofi-passage never calls `age` directly.
- age-agent (optional): `age-agent status --json` is used when installed; without it, every feature still works through the per-run fallback (see Unlocking).

## Store and entry format contract

This contract is shared by passage, PassPony, the migration script, rofi-passage and the GUI; the same section appears in the GUI spec. It follows the pass convention as PassPony's parser (PassPonyCore `pass-core`) reads it, so phone autofill keeps working.

**Store**

- Root: `$PASSAGE_DIR`, default `~/.passage/store`. An entry is `<name>.age`; its name is the path without the extension.
- Ignored when listing: `.git/`, `.age-recipients`, `.gitattributes`, `.extensions/`, symlinks (the audit showed committed symlinks can redirect writes).
- Naming: `<category>/<domain>` for a site's only account, `<category>/<domain>/<label>` for each further account. `<domain>` is the bare domain without `www.`; `<label>` contains no dot (`1`, `perso`, `work`).
- Site matching: the site of an entry is its deepest path component containing a dot, the same rule PassPony uses for autofill.

**Entry content** (UTF-8, LF line endings, final newline)

```text
S3cret-password
username: alice@example.com
url: https://www.example.com
security question: blue
recovery: 1234 5678
recovery: 2345 6789
otpauth://totp/example.com:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=example.com
```

| Line | Rule |
| --- | --- |
| Line 1 | The password. In a TOTP-only entry, the `otpauth://` URI itself, as `pass otp insert` writes it |
| `key: value` lines | Key = text before the first `:`, trailing spaces trimmed; value = the rest, one leading space removed. Repeated keys are kept in order |
| `username:` | Written by every tool. `login:` is accepted when reading, as PassPony does |
| `url:` | Full URL, informational; matching uses the entry name |
| `recovery:` | One line per unused recovery code |
| `otpauth://…` | Last line by convention; when reading, the first `otpauth://` line anywhere wins. Defaults: 6 digits, 30 s, SHA1 |
| Any other line | Free text, preserved byte for byte |

**Writer rules**

- Change only the lines being edited; every other byte stays, so a phone or another device's tool can round-trip the entry.
- Never reorder or rewrite unknown lines; never add keys the user did not ask for.
- Writes go through `passage insert -m -f` (rofi-passage) or the same encryption rules passage uses (GUI): the nearest `.age-recipients`, or `PASSAGE_RECIPIENTS_FILE` / `PASSAGE_RECIPIENTS` when set.

## User flows

Every run starts at the entry menu, which lists names without decrypting anything; a decryption happens only once the user picks an action.

1. **Hotkey** runs `rofi-passage`.
2. **Entry menu:** entry names from the store, fuzzy-matched. Enter runs the default action; a hotkey runs any other action directly; `Alt+m` opens the action menu for the selected entry.
3. **Unlock check:** before the first decryption, if age-agent is locked, rofi-passage asks the passphrase through its pinentry and unlocks it over age-agent's socket, so no prompt ever waits behind the launcher. Without age-agent, rofi-passage unlocks for this run only (see Unlocking).
4. **Action** runs, then rofi-passage exits. A notification confirms copies ("Password copied, clears in 45 s") and errors.

| Action | Default key | What happens |
| --- | --- | --- |
| Autotype | `Enter` | Types `username`, Tab, password, Enter into the focused window. Sequence configurable per entry with an `autotype:` field, e.g. `autotype: username :tab password :tab otp :enter` |
| Copy password | `Alt+1` | Line 1 to the clipboard, cleared after 45 s |
| Copy username | `Alt+2` | `username:` (or `login:`) value |
| Copy TOTP code | `Alt+3` | Code from the `otpauth://` line; if fewer than 5 s remain in its period, waits for the next code |
| Type password | `Alt+4` | Password only, no Enter |
| Type TOTP code | `Alt+5` | For 2FA screens |
| Open URL | `Alt+u` | `url:` value in the default browser through `xdg-open`, only `https://` and `http://` schemes |
| Recovery codes | action menu | Lists codes masked as `recovery 1 (… 5678)`; Enter copies the full code; "Copy and remove" deletes that line from the entry and commits |
| Show fields | action menu | Non-secret fields only (`username`, `url`, custom keys); line 1, `recovery` and `otpauth` stay masked |
| New entry | `Alt+n` | Category picker (existing folders), domain, username, generated password (length 25 by default), optional URL; saves with `passage insert -m`, then copies the password for the signup form |
| Generate new password | action menu | `passage generate -i`: replaces line 1 only, keeps every other line, copies the new password |
| Sync | `Alt+s` | `passage git pull --rebase`, then `push`; the result shown as a notification |

## Unlocking, with or without age-agent

age-agent is optional: every action works without it, and installing it only cuts prompts from one per run to one per session. rofi-passage never asks in a terminal and never writes a decrypted identity to disk, whichever mode applies.

| Identity setup | How rofi-passage decrypts | Prompts |
| --- | --- | --- |
| age-agent set up (`age-agent setup` wrote a stub identities file) | `passage show` with the stub file; unlock over the socket with a pinentry passphrase when locked | Once per session |
| Passphrase-protected identity file, no age-agent | Per-run unlock (UNL-2 to UNL-4) | Once per run |
| Plaintext identity file | `passage show` directly | None; `--check` warns that the key is unprotected at rest |
| Plugin identity only (for example YubiKey) | `passage show` directly; the plugin handles PIN and touch | As the plugin decides |

| ID | Requirement | Priority |
| --- | --- | --- |
| UNL-1 | Mode detection, in order: `age-agent` and `age-plugin-agent` on `PATH`, `age-agent status --json` exits 0, 1 or 2, and either the identities file holds `AGE-PLUGIN-AGENT-` stubs, or it is the encrypted file that age-agent's `config.toml` serves, in which case passage gets age-agent's stub file (`~/.config/age-agent/identities.txt`) whatever the environment says → agent mode. Otherwise read the identities file (`PASSAGE_IDENTITIES_FILE`, default `~/.passage/identities`): an age-encrypted file → per-run mode; `AGE-SECRET-KEY-` lines → plaintext mode; only `AGE-PLUGIN-` lines → plugin mode; missing or unreadable → a notification naming the file | Must |
| UNL-2 | Per-run unlock: ask the passphrase through pinentry (configurable, default `pinentry`, which picks the launcher's own pinentry when installed — `pinentry-rofi`, `pinentry-bemenu` — else the first graphical one), then run `age -d` on the identities file with a private pseudo-terminal as its controlling terminal, answer its prompt there, and read the decrypted identity from a stdout pipe | Must |
| UNL-3 | The decrypted identity lives only in a sealed `memfd` (no writes, no resize after filling) and reaches passage as `PASSAGE_IDENTITIES_FILE=/dev/fd/N` through an inherited descriptor. It is closed when the run ends and never touches disk, argv or the environment (only the `/dev/fd` path does) | Must |
| UNL-4 | One passphrase serves every decryption of a run (for example REC-2's write and verify). The passphrase sits in a `bytearray` that is overwritten after use; 3 attempts; 60 s prompt timeout; cancel stops the action without side effects | Must |
| UNL-5 | `rofi-passage --check` reports the active mode and, in per-run mode, that installing age-agent would reduce prompts | Should |

While a per-run unlock lasts (seconds), a process running as the same user could read the identity through `/proc/<pid>/fd`. That window matches an unlocked age-agent, except that a copy taken in it stays usable; age-agent removes even that window.

Prototyped on 2026-11-01 with `age` and passage 1.7.4: one passphrase served two `passage show` calls through `/dev/fd/N`, and nothing was written to disk. `rage` draws its own pinentry screen instead of a plain prompt, so UNL-2 uses `age` for the unlock step.

## Functional requirements

Must items make 1.0; Should items follow in 1.x; Could items wait for demand.

| ID | Requirement | Priority |
| --- | --- | --- |
| LST-1 | List entry names from the store per the contract (ignored files, no symlinks), without decrypting anything | Must |
| LST-2 | Most-recently-used entries first, from a cache of names only (`$XDG_CACHE_HOME/rofi-passage/mru`, mode 600, no secrets) | Should |
| LST-3 | Several stores in the config, switched with a key, each with its own `PASSAGE_DIR` | Could |
| DEC-1 | Every read goes through `passage show <name>`; output is held in memory only, never written to a file | Must |
| DEC-2 | Before the first decryption of a run, pick the unlock mode (UNL-1); in agent mode, if the agent is locked (or not running: start it with `age-agent daemon`), ask the passphrase through pinentry and send age-agent's socket `unlock` request with the current lock epoch, 3 attempts; stop on cancel. `age-agent unlock` is not used: it prompts on a terminal only | Must |
| DEC-3 | Without age-agent, a passphrase-protected identity is unlocked once per run (UNL-2 to UNL-4); only a missing or unreadable identity ends in an error notification | Must |
| CLP-1 | Copy through `wl-copy --sensitive` on Wayland (wl-clipboard 2.3.0 or newer, so clipboard managers such as cliphist skip it) and `xclip` on X11; the value goes through stdin | Must |
| CLP-2 | Clear after the timeout (default 45 s) only if the clipboard still holds the copied value, then restore the previous text content | Must |
| TYP-1 | Autotype through the configured typing tool, text through stdin, with a configurable delay before the first key (default 100 ms) to let the launcher close | Must |
| TYP-2 | Per-entry `autotype:` field with the tokens `username`, `password`, `otp`, `:tab`, `:enter`, `:space`, `:delay`; unknown tokens abort with a notification, never typed literally | Must |
| TOT-1 | Compute TOTP codes in-process (RFC 6238) from the `otpauth://` line: `secret`, `digits` 6 to 8, `period`, `algorithm` SHA1, SHA256 or SHA512 | Must |
| TOT-2 | `otpauth://hotp/` URIs show an explanatory error; HOTP is out of scope | Should |
| REC-1 | Recovery codes listed masked, copied on Enter | Must |
| REC-2 | "Copy and remove" deletes exactly that `recovery:` line, rewrites the entry through `passage insert -m -f`, then re-reads it and compares it with the expected bytes (passage commits on write) | Should |
| NEW-1 | New-entry flow per User flows; refuses names that break the contract (a dot in the label, `www.` prefix, `..`) with a short reason | Must |
| GEN-1 | Regenerate the password with `passage generate -i` | Should |
| SYN-1 | Sync with `passage git pull --rebase` then `push`; a failed pull never pushes | Should |
| NTF-1 | Notifications through `notify-send`: confirmations, errors, clipboard clear. Never a secret in a notification | Must |

## Security requirements

Entry contents and entry names are untrusted input: anyone with push access to the git remote can write both, and age does not authenticate who encrypted a file. The rules below close the holes found in the rofi-pass and passage reviews.

| ID | Requirement | Origin |
| --- | --- | --- |
| SEC-1 | No code path executes, evaluates or shell-interprets text from an entry or its name. Child processes take argument lists, never a shell string | rofi-pass runs an entry's `otp_method:` line with `bash -c` |
| SEC-2 | No secret in any process's argv or environment. Passwords, codes and new entry contents go through stdin: `wl-copy`, `xclip`, `wtype -`, `xdotool type --file -`, `ydotool type --file -`, `passage insert -m`. TOTP is computed in-process, so no `oathtool <secret>` | argv is readable by other processes in `/proc` |
| SEC-3 | Entry names reach the launcher as plain text: markup rows off, control characters and newlines stripped, names passed to passage after `--` | Names are attacker-controllable through git |
| SEC-4 | Symlinks are skipped when listing and refused when writing; names containing `..` are refused | passage audit: committed symlinks redirect writes |
| SEC-5 | The launcher never receives a secret value. Selections are not stored in launcher history; the MRU cache holds names only | Launcher caches persist on disk |
| SEC-6 | The clipboard-clear helper keeps only a SHA-256 of the copied value, not the value. Secrets are dropped as soon as the action ends and the process exits | Long-lived copies in memory |
| SEC-7 | Never use a prompt the user cannot see: no terminal prompt and no `age` reading a `/dev/tty` that is not there. Prompts come from age-agent's pinentry or rofi-passage's own (UNL-2), time out after 60 s, and a cancel stops the action cleanly | A hidden prompt hangs the launcher |
| SEC-8 | `Open URL` accepts only `https://` and `http://` values and passes the URL as one argument to `xdg-open` | `url:` is untrusted |
| SEC-9 | Notifications never contain a secret, only entry names and outcomes | Notification daemons log history |
| SEC-10 | The config file is parsed as TOML, never sourced or executed | rofi-pass sources a shell config |
| SEC-11 | After a REC-2 rewrite, the re-read entry must equal the original minus that one line; on any difference, the original content is written back and the user is notified | Byte-faithful writer rule |

## CLI, configuration and key bindings

One command with optional flags, so a window manager can bind a hotkey straight to an action: `bindsym $mod+p exec rofi-passage` and `bindsym $mod+Shift+p exec rofi-passage --action copy-totp`.

| Flag | Effect |
| --- | --- |
| `--action ACTION` | Skip the action choice: `autotype`, `copy-password`, `copy-username`, `copy-totp`, `type-password`, `type-totp`, `open-url`, `new`, `sync` |
| `--entry NAME` | Skip the entry menu (scripts, keybindings to a favourite) |
| `--last` | Reuse the last selected entry |
| `--store NAME` | Use a named store from the config (LST-3) |
| `--launcher NAME` | Override the configured launcher |
| `--check` | Print detected launcher, clipboard and typing tools, agent status and store path, then exit |

**Config file** (`~/.config/rofi-passage/config.toml`; every key optional)

```toml
store = "~/.passage/store"          # default: $PASSAGE_DIR, then ~/.passage/store
launcher = "auto"                   # auto | rofi | fuzzel | wofi | bemenu
typing_tool = "auto"                # auto | wtype | ydotool | xdotool
clipboard_timeout = 45              # seconds
default_action = "autotype"
autotype = "username :tab password :enter"   # used when an entry has no autotype: field
type_delay_ms = 100
password_length = 25
use_agent = true
pinentry = "pinentry"               # launcher's own pinentry, else first graphical one

[keys]                              # rofi only; other launchers show the action menu
copy_password = "Alt+1"
copy_username = "Alt+2"
copy_totp = "Alt+3"
type_password = "Alt+4"
type_totp = "Alt+5"
open_url = "Alt+u"
new = "Alt+n"
sync = "Alt+s"
action_menu = "Alt+m"
```

**Launcher adapters**

- rofi (2.0 or newer for Wayland): `-dmenu` with `-kb-custom-N`; rofi's exit code 10 + N tells which hotkey was used.
- fuzzel, wofi, bemenu: plain dmenu mode with no custom keys. Enter opens the action menu, with the default action first so Enter, Enter still takes two keys.

## Dependencies and display servers

`auto` picks the first available tool in each cell's order; `rofi-passage --check` prints what it found.

| Need | X11 (i3, Openbox, …) | Wayland, wlroots (sway, Hyprland, river) | Wayland, GNOME or KDE |
| --- | --- | --- | --- |
| Launcher | rofi | rofi 2.0+, fuzzel, wofi, bemenu | rofi 2.0+, fuzzel |
| Clipboard | xclip | wl-copy 2.3.0+ (`--sensitive`) | wl-copy 2.3.0+ |
| Typing | xdotool | wtype, then ydotool | ydotool (needs `ydotoold` and uinput access); wtype on KDE to be verified |
| Notifications | notify-send | notify-send | notify-send |
| Open URL | xdg-open | xdg-open | xdg-open |

Always required: Python 3.11 or newer (stdlib only), FiloSottile's passage, git. Optional: age-agent, for one prompt per session instead of one per run.

GNOME's compositor does not offer the virtual-keyboard protocol wtype uses, so typing there goes through ydotool, which writes to `/dev/uinput` and therefore needs its daemon and a udev rule or group membership. The README documents that setup; copy actions work without it.

## Implementation, testing and acceptance

Python 3.11+ with the standard library only. Bash was ruled out: computing TOTP in-process and keeping every secret off argv needs HMAC and careful subprocess handling, which bash cannot do without a helper that takes the secret as an argument.

**Modules**

| Module | Responsibility |
| --- | --- |
| `store` | Listing, naming rules, symlink and `..` checks |
| `entry` | Parser and byte-faithful writer for the format contract |
| `totp` | RFC 6238 with SHA1, SHA256, SHA512 |
| `launcher` | rofi, fuzzel, wofi, bemenu adapters |
| `clipboard`, `typer` | Tool detection, stdin-only I/O, clear-after-timeout helper |
| `agent` | Unlock mode detection (UNL-1); `age-agent status --json`, stub lookup and the socket `unlock`; the per-run fallback: pinentry, pseudo-terminal `age -d`, sealed memfd |
| `actions`, `cli` | Flows and flags |

**Tests**

- Unit: `entry` against a shared fixture corpus (the same files the GUI tests use, also checked against PassPony's `pass-core` parser); `totp` against the RFC 6238 test vectors; naming-rule edge cases.
- Integration: a temporary store with a plaintext test identity; every action run under Xvfb with xdotool and under headless sway with wtype; launchers replaced by a scripted fake that returns chosen lines and exit codes.
- Security: during the whole integration suite, a watcher samples `/proc/*/cmdline` and `/proc/*/environ` and fails on any test secret; a test entry named with markup and control characters renders as plain text.
- Lint: `ruff`, `mypy --strict`.

**Acceptance criteria for 1.0**

- [ ] Hotkey, three letters, Enter autotypes a login on sway and on i3.
- [ ] With age-agent locked, the first action shows one pinentry prompt; with age-agent not installed, each run shows one pinentry prompt and no file containing the identity appears on disk. No terminal prompt in either case.
- [ ] No test secret ever appears in argv or environment during the suite.
- [ ] cliphist does not record a copied password; the clipboard is cleared after 45 s unless the user copied something else meanwhile.
- [ ] An entry created by PassPony keeps every byte except the removed line after "Copy and remove".

**Milestones**

1. **M1:** list, copy password and username, unlocking with and without age-agent, X11 and Wayland clipboard.
2. **M2:** autotype, TOTP, recovery codes, typing-tool detection.
3. **M3:** new entry, regenerate, sync, MRU, notifications.
4. **M4 — 1.0:** packaging (AUR, pipx), README with compositor setup notes.

**Open questions**

- [ ] Does KWin (Plasma 6) accept wtype's virtual keyboard, or does KDE need ydotool like GNOME?
- [ ] Restore only text when clearing the clipboard, or also images and other types? Current choice: text only.
- [ ] Does fuzzel offer custom key bindings in dmenu mode, which would avoid the action-menu round trip?
- [ ] Should the shared fixture corpus live in its own small repo that both rofi-passage and the GUI pull in?

**Later versions:** hardware-bound device identities (`age1tag1…` recipients from age-plugin-tpm or the Secure Enclave) are a path to explore after 1.0. rofi-passage already handles them through plugin mode; the age-agent spec lists the questions to answer before adopting them.
