# True positive: JWT alg=none, the canonical signature-bypass token forgery.
import jwt


def verify(token: str) -> dict:
    return jwt.decode(token, key="", algorithm="none")
