# False positive: subprocess invoked with a list (no shell), which is safe.
# The risky-diff rule's `subprocess-shell` family covers both `subprocess.`
# imports and `shell=True`. This file uses neither in a risky way, so it
# is expected to be flagged at most as MEDIUM (informational) — never
# CRITICAL/HIGH.
import shlex
import subprocess


def list_files(directory: str) -> str:
    args = ["ls", "-la", shlex.quote(directory)]
    return subprocess.check_output(args, text=True)
