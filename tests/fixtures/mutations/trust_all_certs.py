# Mutation fixture: trust-all certificates.
# Expected detection: AI-TRUSTALLCERTS or AUTH-VERIFY-FALSE.

import ssl
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_unverified_context():
    ctx = ssl._create_unverified_context()
    return ctx
