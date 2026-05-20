"""Mutation-style regression fixtures for AI-generated failure patterns (#59).

Each file in this directory simulates a *category* of AI-introduced
regression — auth commented out, CORS opened to ``*``, SSL verification
disabled, JWT alg=none, hardcoded admin creds, stub credentials,
package include lists widened, eval-with-input, etc. The intent is that
VibeGuard's rules must keep catching these characteristic patterns even
as rule internals are refactored.

These files are intentionally vulnerable; ``tests/`` is ignored by the
self-scan in ``vibeguard.yaml`` so they don't trip the gate.
"""
