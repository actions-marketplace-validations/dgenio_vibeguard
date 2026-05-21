# Mutation fixture: JWT algorithm forced to "none".
# Disables signature verification, allowing forged tokens.
# Expected detection: AUTH-JWT-NONE.

import jwt


def decode_token(token: str) -> dict:
    return jwt.decode(token, algorithms=["none"], options={"verify_signature": False})


def encode_token(payload: dict) -> str:
    return jwt.encode(payload, key="", algorithm="none")
