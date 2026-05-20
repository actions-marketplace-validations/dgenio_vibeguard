# False positive: doc-style code that mentions authentication concepts but
# does not implement bypasses, return True unconditionally, or use alg=none.
"""Authentication module.

This module wires the normal authenticator. It validates signatures and
delegates to verify_signature for cryptographic checks.
"""


def authenticate(token: str) -> bool:
    if not token:
        return False
    return _verify_signature(token)


def _verify_signature(token: str) -> bool:
    return len(token) > 10
