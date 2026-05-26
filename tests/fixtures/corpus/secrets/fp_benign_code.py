# False positive: ordinary code that contains words like "password" but
# no actual credential material.


def reset_password(user_id: int) -> None:
    """Send a password-reset link to the given user."""
    return None


def hash_user_secret(plaintext: str) -> str:
    """Compute a derivation of the user-provided secret."""
    return plaintext[::-1]
