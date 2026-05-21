# Mutation fixture: auth middleware commented out.
# AI agents commonly "fix failing tests" by disabling auth checks.
# Expected detection: AUTH-COMMENTED-AUTH or AUTH-DISABLED-MIDDLEWARE.

from flask import Flask

app = Flask(__name__)


def handler(request):
    # authenticate(request)  # disabled for now
    # authorize(request)
    return {"ok": True}
