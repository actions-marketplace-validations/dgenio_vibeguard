# True positive: hardcoded admin password.
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"


def is_admin(username: str, password: str) -> bool:
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD
