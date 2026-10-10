"""Run the install steps from README.md exactly as written.

CI runs this on fresh Windows and Linux machines, so the build instructions
are tested on every change. Usage: python scripts/readme_smoke.py windows|posix
"""

import shutil

# Used only to run the fixed commands written in README.md.
import subprocess  # nosec B404
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"

# CI has already checked out the version under test into the repository root.
# Cloning would fetch main instead of that version, so these lines are skipped.
SKIPPED_PREFIXES = ("git clone ", "cd ")

# Each block runs in the shell a fresh machine has: Windows PowerShell 5.1 on
# Windows, bash elsewhere.
SHELLS = {
    "windows": ("powershell", ["-NoProfile", "-NonInteractive", "-Command"]),
    "posix": ("bash", ["-c"]),
}

TIMEOUT_SECONDS = 900


def extract_commands(readme: str, platform: str) -> list[str]:
    """Return the non-empty lines of the code block after the platform's marker."""
    marker = f"<!-- readme-smoke: {platform} -->"
    lines = readme.splitlines()
    try:
        start = lines.index(marker)
    except ValueError:
        raise SystemExit(f"README.md has no '{marker}' line") from None
    if start + 1 >= len(lines) or not lines[start + 1].startswith("```"):
        raise SystemExit(f"'{marker}' must be followed directly by a code block")
    commands: list[str] = []
    for line in lines[start + 2 :]:
        if line.startswith("```"):
            return commands
        if line.strip():
            commands.append(line.strip())
    raise SystemExit(f"the code block after '{marker}' is not closed")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in SHELLS:
        print(f"usage: {argv[0]} {'|'.join(SHELLS)}", file=sys.stderr)
        return 2
    platform = argv[1]
    shell_name, shell_args = SHELLS[platform]
    shell = shutil.which(shell_name)
    if shell is None:
        print(f"{shell_name} not found", file=sys.stderr)
        return 2

    commands = extract_commands(README.read_text(encoding="utf-8"), platform)
    if not commands:
        print("the README block is empty", file=sys.stderr)
        return 1
    for command in commands:
        if command.startswith(SKIPPED_PREFIXES):
            print(f"skip: {command}", flush=True)
            continue
        print(f"run:  {command}", flush=True)
        # The command comes from our own README, not from outside input.
        # stdin is closed, so an interactive prompt sees end of input and exits.
        result = subprocess.run(  # noqa: S603  # nosec B603
            [shell, *shell_args, command],
            cwd=REPO,
            stdin=subprocess.DEVNULL,
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
        if result.returncode != 0:
            print(f"exit code {result.returncode}: {command}", file=sys.stderr)
            return 1
    print("README install steps passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
