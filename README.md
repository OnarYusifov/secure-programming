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

The prompt accepts only the commands listed by `help`, and a line of at most 256 characters. An
empty line does nothing (it never repeats the last command), and an unknown command is not printed
back, in case it was a password typed at the wrong prompt. Text that comes from a user or a file is
printed without control characters, terminal escape sequences or bidirectional controls, so it
cannot clear the screen, move the cursor or disguise itself. Errors are short messages, never a
traceback. Ctrl-C cancels the command in progress; at the prompt, Ctrl-C or the end of input (Ctrl-D,
or Ctrl-Z then Enter on Windows) exits. The program itself takes no command-line arguments.

Before unlocking:

| Command | Action |
|---|---|
| `register` | Create an account and a vault; prints the recovery key once |
| `login` | Unlock a vault with the master password |
| `recover` | Unlock with the recovery key, then set a new master password and get a new recovery key |
| `quit` | Exit |

`register` asks for a username, then for the master password twice. A username has 3 to 32
characters: lowercase letters a-z, digits, `_` and `-`, starting with a letter or a digit. The
master password needs 12 to 1024 characters and must not be one of the 10 000 most common
passwords (the [SecLists](https://github.com/danielmiessler/SecLists) list, shipped with the
program, checked offline and ignoring case). Creating the vault takes a moment, because the key is
derived with Argon2id. The recovery key is then printed once, as eight groups of four characters.
Write it down: it is not stored anywhere, and it is the only way back in if the master password is
forgotten.

`login` asks for the username and the master password. Every failure, whether an unknown
username, a wrong password or a damaged or swapped vault file, gives the same `Login failed.`, and
each one makes the next attempt wait longer: 1 s, then 2, 4 and so on up to 32 s. After unlocking,
yunarpass prints how many times the vault has been saved. If that number is lower than you
remember, an older copy of the vault file was put back in place. `quit`, Ctrl-C at the prompt and
the end of input lock the vault, which wipes its key from memory.

After unlocking (`yunarpass:<username>>` prompt):

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
| `edit <name>` | Edit an entry: Enter keeps a value, `-` clears it; the password prompt is masked and also accepts `gen` |
| `rm <name>` | Delete an entry, after its name is typed again |
| `gen [length]` | Generate a password (20 characters by default, 12 to 128) with letters, digits and symbols, and copy it to the clipboard; it is never printed |
| `passwd` | Change the master password |
| `lock` | Lock the vault and clear the clipboard; also happens automatically after 5 minutes idle |
| `quit` | Lock and exit |

Entry names have 1 to 64 characters: letters, digits, `.`, `_`, `@` and `-`, starting with a letter
or a digit. No two entries can have the same name, ignoring case, and `show GitHub` finds the entry
`github`. A username can have up to 256 characters, a password 1024, a URL 2048 and the notes 4096;
control characters and terminal escape sequences are refused in all of them. `add` checks each
answer as soon as it is typed and asks for the password twice. `show` prints every field except the
password, which always appears as `********`, whatever its length.

Every change is saved at once: the vault's counter goes up by one, and the vault file is encrypted
again under a fresh nonce and replaced atomically. If another yunarpass prompt logged in to the
same account has saved in the meantime, the change is refused instead of overwriting the other
one; log in again to see the newer version.

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

Every dependency is installed from `requirements.txt` with `--require-hashes`, so pip refuses any
file whose SHA-256 differs from the pinned one. The program itself is then installed with
`--no-deps --no-build-isolation`, so that step downloads nothing: it builds with the hash-checked
`setuptools` installed just before.

Windows (PowerShell or Command Prompt):

<!-- readme-smoke: windows -->
```powershell
git clone https://github.com/OnarYusifov/secure-programming.git
cd secure-programming
python -m venv .venv
.venv\Scripts\python -m pip install --require-hashes -r requirements.txt
.venv\Scripts\python -m pip install --no-deps --no-build-isolation .
.venv\Scripts\python -m yunarpass
```

Linux and macOS:

<!-- readme-smoke: posix -->
```sh
git clone https://github.com/OnarYusifov/secure-programming.git
cd secure-programming
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.txt
.venv/bin/python -m pip install --no-deps --no-build-isolation .
.venv/bin/python -m yunarpass
```

The last line starts the prompt; type `help` there to see the commands. The commands call the
virtual environment's Python directly, so no activation script is needed.
CI runs these blocks verbatim on fresh Windows and Linux machines on every change (`readme-smoke`).

Data is stored in `~/.yunarpass/` (override with the `YUNARPASS_HOME` environment variable).
The directory and every file in it are created readable by the owner only: mode 0700/0600 on
Linux and macOS, and on Windows an access list that names only the current user and inherits
nothing from the parent folder. yunarpass refuses to use the directory, rather than repair it, if
it is a symlink or junction, belongs to another user, or has been opened up to anyone else. It
also refuses a data file that is a link, has a second hard link or is larger than 8 MiB.

Each vault is a JSON file, `vault-<random id>.json`. Its username, vault ID and key-derivation
settings can be read, but they are authenticated, so an edited value makes the vault refuse to
open; the entries and both copies of the data key are encrypted. The format is in
[DESIGN.md §4](DESIGN.md#4-cryptographic-scheme-and-vault-format). `users.json` lists the
usernames with their vault IDs, and nothing else.

Every save writes a temporary file and renames it over the old one, so a crash or power cut leaves
either the old or the new version, never a half-written file. The version before the last save is
kept next to each file as `users.json.bak` or `vault-<id>.json.bak`.

Development, with the virtual environment activated (`.venv\Scripts\activate` on Windows,
`source .venv/bin/activate` elsewhere; if PowerShell refuses to run the script, allow it once with
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`):

```sh
pip install --require-hashes -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .
ruff check .
mypy
bandit -r src
pytest --cov
```

`pytest --cov` measures branch coverage and fails below 80%; plain `pytest` skips the measurement.
Locally it counts the other OS's code (Windows ACLs, POSIX modes) as not covered; CI applies the
80% floor to the Windows and Linux runs combined.

To change a runtime dependency, edit `requirements.in` and regenerate the lock file on Windows, so
the Windows-only `pywin32` pin keeps its marker:

```sh
python -m piptools compile --generate-hashes --allow-unsafe --strip-extras --no-emit-index-url requirements.in
```

The same checks run in CI on every pull request and every push to `main`: lint and security scans
once, a [gitleaks](https://github.com/gitleaks/gitleaks) secret scan over the whole git history,
type checks and tests on Ubuntu and Windows with Python 3.12 and 3.14, and a coverage job that
combines the four test runs and checks the 80% floor. The `ci-ok` job passes only when all of them
pass, and `main` requires it. With gitleaks installed, the secret scan runs locally as
`gitleaks git --redact .`.

## Status

| Checkpoint | Due | State |
|---|---|---|
| 1. Threat model and architecture | 25 Sep 2026 | Done: [DESIGN.md](DESIGN.md) |
| 2. Core implemented | 30 Oct 2026 | In progress: [PROGRESS.md](PROGRESS.md) |
| 3. Near-final | 20 Nov 2026 | Not started |
