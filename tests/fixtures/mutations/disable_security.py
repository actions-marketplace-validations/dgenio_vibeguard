# Mutation fixture: explicit "disable security" toggle.
# Expected detection: AI-DISABLESECURITY.


SECURITY = False  # disable security for local testing


def is_request_allowed(req) -> bool:
    if not SECURITY:
        return True
    return False
