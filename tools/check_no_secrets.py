"""Refuse commits that would track secret material.

Runs as a pre-commit hook (see .git/hooks or the setup snippet in
docs/security-hardening.md). It checks:

  * nothing under .env* is staged (templates like .env.sample are fine)
  * nothing named like a key/credential file is staged
  * no staged file contains a detected signing-key/credential block
    (Integration: works for any git version with `git diff --cached`.)
"""
from __future__ import annotations

import re
import subprocess
import sys

# Paths that must never be staged. `.env.sample` is allowed explicitly
# because it ships placeholders, not secrets.
FORBIDDEN_PATHS = re.compile(
    r"""
    (^|/)?\.env$            # the real env file, whatever sits next to it
    | \.env\.[^.]+$         # .env.local, .env.prod — anything but .sample
    | \.pem$
    | \.p12$ | \.pfx$
    | _rsa$ | _ed25519$ | id_dsa$
    | credentials?\.json$
    | secrets?\.ya?ml$
    """,
    re.VERBOSE,
)

# Content patterns: private key blocks and obvious hardcoded secrets.
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    re.compile(r"(?i)\b(secret|password|api[_-]?key|token)\b['\"]?\s*[:=]\s*['\"][A-Za-z0-9+/=_\-]{24,}"),
]


def staged_files() -> list[str]:
    out = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True, text=True, check=True,
    )
    return [f for f in out.stdout.splitlines() if f]


def file_contents(path: str) -> str:
    out = subprocess.run(
        ["git", "show", f":{path}"],
        capture_output=True, text=True, check=False,
    )
    return out.stdout


def main() -> int:
    problems: list[str] = []

    for path in staged_files():
        if FORBIDDEN_PATHS.search(path) and not path.endswith(".sample"):
            problems.append(f"forbidden path staged: {path}")
            continue
        blob = file_contents(path)
        for pattern in SECRET_PATTERNS:
            if pattern.search(blob):
                problems.append(f"possible secret in staged file: {path}")
                break

    if problems:
        print("commit refused — secret material detected:\n", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(
            "\nIf this is a false positive, add an inline waiver on the line "
            "(# notcs: allow) and re-run.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
