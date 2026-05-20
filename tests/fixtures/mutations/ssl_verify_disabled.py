# Mutation fixture: SSL verification disabled in requests calls.
# AI agents often "fix" SSL errors by passing verify=False.
# Expected detection: AUTH-VERIFY-FALSE (or RISK-TRUSTCERTS).

import requests


def fetch(url: str) -> str:
    response = requests.get(url, verify=False, timeout=5)
    return response.text
