# Deliberately unsafe — benchmark fixture only.
import subprocess

import requests


def run_command(user_input: str) -> str:
    # temporary bypass — skip validation for now
    result = subprocess.run(user_input, shell=True, capture_output=True, text=True)
    return result.stdout


def fetch(url: str):
    return requests.get(url, verify=False)


def lookup(conn, user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query)
