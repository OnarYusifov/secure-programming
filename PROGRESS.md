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

Due 30 Oct 2026. **In progress**, tracked in the
[CP2 milestone](https://github.com/OnarYusifov/secure-programming/milestone/1).

Scope changes at the start of the checkpoint, so that the interface never prints a password (the
CP2 brief): `copy` moved here from Checkpoint 3, `show --reveal` was removed, and `gen` never
prints. Details and reasons are in [DESIGN.md §6](DESIGN.md#6-as-built).

The full note is written at the end of the checkpoint (#29): each brief requirement with its
evidence, a demo script, test and coverage numbers, and the known gaps.

## Checkpoint 3: near-final state

Due 20 Nov 2026. Not started.
