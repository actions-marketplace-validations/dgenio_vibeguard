# True positive: SSL verification turned off.
import requests


def call_api(url: str) -> str:
    return requests.get(url, verify=False, timeout=5).text
