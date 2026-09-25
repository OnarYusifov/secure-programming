# yunarpass

A local, multi-user password manager for the terminal. Semester project for ICS0022 Secure
Programming (TalTech, autumn 2026).

Each user has their own vault, encrypted with a key derived from their master password. The vault
also stores TOTP secrets and SSH private keys, so passwords, second factors and keys never lie
around in plaintext files. A paper recovery key, shown once at registration, is the only way back
in if the master password is forgotten.

Design document: [DESIGN.md](DESIGN.md) (assets, architecture, threat model, crypto scheme).

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
| `add <name>` | Add a login entry (prompts for username, password or `gen`, URL, notes) |
| `add-totp <name>` | Add a TOTP secret |
| `add-ssh <name> <path>` | Import an SSH private key file into the vault |
| `list` | List entry names and types, never secrets |
| `show <name>` | Show an entry; the password is masked unless `--reveal` is given |
| `copy <name>` | Copy the password to the clipboard; cleared after 20 s |
| `totp <name>` | Show the current TOTP code |
| `ssh-load <name>` | Load the key into `ssh-agent` for 10 minutes |
| `edit <name>` | Edit an entry |
| `rm <name>` | Delete an entry, after confirmation |
| `gen [length]` | Generate a password (default 20 characters) |
| `passwd` | Change the master password |
| `lock` | Lock the vault; also happens automatically after 5 minutes idle |
| `quit` | Lock and exit |

Checkpoint 2 delivers `register`, `login`, `recover`, the login entries, `gen`, `passwd`, `lock`
and auto-lock. Checkpoint 3 adds `copy`, TOTP, SSH keys and a full-screen TUI (Textual) on top of
the same core.

## Build and run

Requirements: Python 3.12 or newer. For `ssh-load`, OpenSSH with a running `ssh-agent`
(on Windows: the *OpenSSH Authentication Agent* service).

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
ruff check . && mypy . && bandit -r src && pytest
```

The same checks run in CI on every pull request.

## Status

| Checkpoint | Due | State |
|---|---|---|
| 1. Threat model and architecture | 25 Sep 2026 | Done: [DESIGN.md](DESIGN.md) |
| 2. Core implemented | 30 Oct 2026 | Not started |
| 3. Near-final | 20 Nov 2026 | Not started |
