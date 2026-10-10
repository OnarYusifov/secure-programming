# yunarpass

A local, multi-user password manager for the terminal. Semester project for ICS0022 Secure
Programming (TalTech, autumn 2026).

Each user has their own vault, encrypted with a key derived from their master password. The vault
also stores TOTP secrets and SSH private keys, so passwords, second factors and keys never lie
around in plaintext files. A paper recovery key, shown once at registration, is the only way back
in if the master password is forgotten.

Design document: [DESIGN.md](DESIGN.md) (assets, architecture, threat model, crypto scheme,
deviations as built, threat-to-code map). Progress notes per checkpoint: [PROGRESS.md](PROGRESS.md).

## Scope

In scope:

- Multi-user accounts on one machine, one encrypted vault file per user
- Entries of three types: logins (username, password, URL, notes), TOTP secrets, SSH private keys
- Password generation with a CSPRNG
- Copy to clipboard with automatic clearing
- Auto-lock after inactivity
- Master-password change and recovery with a paper recovery key
- Loading an SSH key into the OS `ssh-agent` with a time limit, without writing it to disk

Out of scope: browser integration, cloud sync, sharing entries between users, and protection
against a compromised operating system or administrator-level malware (see the assumptions in
[DESIGN.md](DESIGN.md#assumptions-and-out-of-scope)).

## Planned commands

The tool is an interactive prompt (REPL). Secrets are always entered at a masked prompt, never as
command-line arguments, so they cannot end up in the shell history or the process list.

Passwords are never printed. `show` masks them, `gen` puts a new password in the clipboard or
straight into an entry, and `copy` is the way to use a stored password. The only secret the tool
ever prints is the recovery key, once, because the user has to write it down.

Before unlocking:

| Command | Action |
|---|---|
| `register` | Create an account and a vault; prints the recovery key once |
| `login` | Unlock a vault with the master password |
| `recover` | Unlock with the recovery key, then set a new master password and get a new recovery key |
| `quit` | Exit |

After unlocking (`yunarpass>` prompt):

| Command | Action |
|---|---|
| `add <name>` | Add a login entry: prompts for username, password (masked; type `gen` to generate one), URL and notes |
| `add-totp <name>` | Add a TOTP secret |
| `add-ssh <name> <path>` | Import an SSH private key file into the vault |
| `list` | List entry names and types, never secrets |
| `show <name>` | Show an entry; the password is always masked |
| `copy <name>` | Copy the password to the clipboard; cleared after 20 s, and kept out of the clipboard history on Windows |
| `totp <name>` | Show the current TOTP code |
| `ssh-load <name>` | Load the key into `ssh-agent` for 10 minutes |
| `edit <name>` | Edit an entry; the password prompt is masked and also accepts `gen` |
| `rm <name>` | Delete an entry, after confirmation |
| `gen [length]` | Generate a password (default 20 characters) and copy it to the clipboard; it is never printed |
| `passwd` | Change the master password |
| `lock` | Lock the vault and clear the clipboard; also happens automatically after 5 minutes idle |
| `quit` | Lock and exit |

Checkpoint 2 delivers `register`, `login`, `recover`, the login entries (`add`, `list`, `show`,
`edit`, `rm`), `copy`, `gen`, `passwd`, `lock` and auto-lock. Checkpoint 3 adds TOTP, SSH keys and a
full-screen TUI (Textual) on top of the same core. `copy` was planned for Checkpoint 3 but moved
into Checkpoint 2: the CP2 brief requires an interface that never prints passwords, and without
printing, the clipboard is the only way to get a password out (see
[DESIGN.md §6](DESIGN.md#6-as-built)).

## Build and run

Requirements: Python 3.12 or newer. Windows 10/11 is the primary platform, used for development
and the demo; Linux is also supported and tested in CI.

- For `copy` on Linux: `wl-copy` (Wayland) or `xclip` (X11). Windows and macOS need nothing extra.
- For `ssh-load` (Checkpoint 3): OpenSSH with a running `ssh-agent` (on Windows: the *OpenSSH
  Authentication Agent* service).

```sh
git clone https://github.com/OnarYusifov/secure-programming.git
cd secure-programming
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux / macOS
pip install --require-hashes -r requirements.txt
python -m yunarpass
```

Data is stored in `~/.yunarpass/` (override with the `YUNARPASS_HOME` environment variable).
The directory and every file in it are created readable by the owner only.

Development:

```sh
pip install -r requirements-dev.txt
pip install -e .
ruff check .
mypy
bandit -r src
pytest --cov
```

`pytest --cov` measures branch coverage and fails below 80%; plain `pytest` skips the measurement.

The same checks run in CI on every pull request and every push to `main`: lint and security scans
once, and type checks and tests on Ubuntu and Windows with Python 3.12 and 3.14. The `ci-ok` job
passes only when all of them pass, and `main` requires it.

## Status

| Checkpoint | Due | State |
|---|---|---|
| 1. Threat model and architecture | 25 Sep 2026 | Done: [DESIGN.md](DESIGN.md) |
| 2. Core implemented | 30 Oct 2026 | In progress: [PROGRESS.md](PROGRESS.md) |
| 3. Near-final | 20 Nov 2026 | Not started |
