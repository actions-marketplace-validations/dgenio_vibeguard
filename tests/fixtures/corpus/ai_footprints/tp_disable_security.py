# True positive: explicit security-disable footprint matching the AI rule's
# `disable security` / `security = False` pattern.

security = False  # disable security for local testing


def request_handler(req):
    # skip auth for local dev
    return {"ok": True}
