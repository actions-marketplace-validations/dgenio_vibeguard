# True positive: shell=True in subprocess call.
import subprocess


def run(cmd: str) -> int:
    result = subprocess.run(cmd, shell=True, check=False)
    return result.returncode
