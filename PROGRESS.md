# Progress notes

One section per checkpoint of the project: what was delivered, where the evidence is, and what
changed from the plan.

## Checkpoint 1: threat model and architecture

Due 25 Sep 2026. **Done**, merged on 25 Sep 2026.

- [DESIGN.md](DESIGN.md) §1–§5: nine assets; the architecture with its components, trust
  boundaries and unlock data flow; a misuse-case threat model with 24 rated threats (T1–T24), each
  with a mitigation and its residual risk; the cryptographic scheme and vault file format; the
  choice of language and libraries.
- [README.md](README.md): scope, planned commands, build and run instructions.
- CI in GitHub Actions on every pull request and every push to `main`: `ruff`, `mypy --strict`,
  `bandit`, `pip-audit` and `pytest`, with a package skeleton for the pipeline to check.

Process: one GitHub issue per unit of work (#1–#4, #10), each closed by its own pull request
(#5–#9, #11).

## Checkpoint 2: core requirements implemented

Due 30 Oct 2026. **Core requirements done** on `main` on 11 Oct 2026. The desktop GUI that
replaces the planned TUI is still in progress (#43–#47). Tracked in the
[CP2 milestone](https://github.com/OnarYusifov/secure-programming/milestone/1).

### The brief, requirement by requirement

| CP2 brief (Projects.pdf §4.4.2) | Evidence |
|---|---|
| Basic vault storage working | One vault file per user and an index, `users.json`, in a data directory only the owner can open. Every change is saved at once: written to a temporary file and renamed over the old one, with the previous version kept as `.bak`, and refused if another session saved in between. Code: `storage.py`, `vaultfile.py`, `users.py`, `session.py`. Tests: `test_storage.py`, `test_vaultfile.py`, `test_session.py`, and `test_cli.py::test_entries_persist_after_quit` |
| Simple credentials encrypted at rest using the chosen scheme | The scheme of [DESIGN.md §4](DESIGN.md#4-cryptographic-scheme-and-vault-format): the entries are encrypted with AES-256-GCM under a random data key (DEK), which is stored only wrapped, once under a key derived from the master password with Argon2id and once under a key derived from the recovery key with HKDF. No plaintext is written to disk, not even to a temporary file. Code: `crypto.py`, `vaultfile.py`. Tests: known-answer tests from RFC 9106 and RFC 5869 in `test_crypto.py`; `test_no_entry_text_appears_in_the_file` in `test_vaultfile.py` and `test_session.py` |
| Master password authentication; the vault unlocks only on successful verification | The key derived from the password must unwrap the DEK, which AES-GCM authenticates. A wrong password, an unknown username, a damaged vault and an edited header all fail with the same `Login failed.`, after one Argon2id run each and a delay that doubles from 1 s up to 32 s. Before login, the only commands are `register`, `login`, `recover`, `help` and `quit`. Code: `users.py` (`Accounts.login`, `Backoff`), `vaultfile.py` (`unlock_with_password`). Tests: `test_users.py::test_every_failed_login_looks_the_same_and_costs_one_kdf_run`, `test_a_tampered_vault_fails_like_a_wrong_password`, `test_failed_logins_wait_longer_each_time_up_to_the_cap` |
| A usable interface that never prints passwords in cleartext | A prompt with `help`, short error messages and masked input. The views of an entry that the session hands to the interface have no password field, `show` prints `********`, and `copy` and `gen` put a password on the clipboard, which is cleared after 20 s and kept out of the Windows clipboard history. Every printed line is stripped of control characters and terminal escape sequences. The only secret ever printed is the recovery key, once, so that the user can write it down. Code: `cli.py`, `entries.py` (`EntryView`), `clipboard.py`. Tests: `test_cli.py::test_no_password_is_ever_printed`, `test_copy_puts_the_password_on_the_clipboard_and_never_prints_it`, `test_gen_copies_a_new_password_and_never_prints_it`; `test_entries.py::test_views_have_no_password` |
| Build and run instructions that work on a clean machine | [README.md, *Build and run*](README.md#build-and-run). The `readme-smoke` CI job runs the README's install commands verbatim on fresh Windows and Linux runners on every change. Also checked by hand on 12 Oct 2026: a fresh clone on Windows 11 with Python 3.14.7, following the README alone |
| A commit history showing incremental progress | Every unit of work is a GitHub issue closed by its own pull request: for this checkpoint, 18 issues (#12–#28 and #57) and their 18 pull requests (#30–#60). Pull requests are merged with rebase, so every small commit lands on `main` with its own date: `git log --reverse main` |

The master password is not "stored with a hashing method such as bcrypt" (Projects.pdf §4.2),
because nothing derived from it is stored at all. Argon2id, a password-hashing function like
bcrypt, derives the key that unwraps the DEK, and AES-GCM checks the result. Argon2id won the
Password Hashing Competition and is memory-hard, at 64 MiB per guess here, whereas bcrypt uses
about 4 KiB and is therefore cheaper to attack with GPUs. A stored hash next to the vault would
also give a thief a second target. Details:
[DESIGN.md §6](DESIGN.md#brief-requirements-met-in-a-different-way).

### Tests and checks

CI on `main` at `ccd736b` (11 Oct 2026), on Windows and Ubuntu with Python 3.12 and 3.14:

- 389 test functions. With their parameters, 750 tests run on Windows, where 749 pass and 1 is
  skipped (the clipboard tool choice of Linux and macOS), and 745 run on Linux, where all pass.
- Branch coverage over the four runs combined: 99% (1640 statements, 334 branches). CI fails below
  80%.
- `ruff`, `mypy` in strict mode, `bandit`, `pip-audit` on the pinned dependencies, and a `gitleaks`
  scan of every commit.

[DESIGN.md §7](DESIGN.md#7-threat--code--test-map) maps every threat to the code and the tests that
handle it.

### Changes since Checkpoint 1

Each change with its reason is in [DESIGN.md §6](DESIGN.md#6-as-built).

- So that the interface never prints a password: `copy` moved here from Checkpoint 3,
  `show --reveal` was removed, and `gen` copies instead of printing (D1–D3).
- Windows is the primary platform. `pywin32` creates the owner-only access lists and puts copies on
  the clipboard so they stay out of its history; `pyperclip` was dropped (D4–D6).
- Found while building: a ceiling on the Argon2id settings (D8), keys in buffers that can be
  zeroed (D9), associated data for each copy of the DEK (D10), a 32 s cap on the login delay (D11),
  and auto-lock driven by each interface (D14).
- Three threats added: a password read from the screen (T25), two sessions overwriting each other's
  saves (T28), and changing the wrong one of two similar entries (T29) (D7, D15, D16).
- The full-screen Textual TUI planned for Checkpoint 3 is being replaced by a desktop GUI
  (PySide6) on the same core. Its first issues (#43–#47) are open in this checkpoint.

### Known gaps and residual risks

For Checkpoint 3:

- TOTP secrets and SSH keys (UC9, UC10; T21, T22).
- Structured logging of key events (Projects.pdf §4.2; T17).
- Secure memory: the KEK and the DEK are zeroed `bytearray`s, but the master password and the
  decrypted entries are Python strings, which cannot be wiped (T13). Core dumps are not switched off
  yet (T14).
- Published release checksums (T24).

Accepted, each in [DESIGN.md §3](DESIGN.md#3-threat-model):

- The login delay is kept by the running program, so a restart starts again at 1 s. Every attempt
  still costs one Argon2id run (T2).
- The recovery key alone opens the vault, by design, and stays in the terminal scrollback after it
  is shown (T5, T25).
- Rolling back every file at once cannot be detected; the save counter shown at login only helps the
  user notice (T9).
- Another process of the same user can read the clipboard during the 20 s (T18).
- `passwd` keeps the DEK, so an older copy of the vault file still opens with the old password
  ([DESIGN.md §4](DESIGN.md#4-cryptographic-scheme-and-vault-format), *Password change*).
- Two saves at the same moment can still race; the overwritten version stays in `.bak` (T28).


## Checkpoint 3: near-final state

Due 20 Nov 2026. Not started.
