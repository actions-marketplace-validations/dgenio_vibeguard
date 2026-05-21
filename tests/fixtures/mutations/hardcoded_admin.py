# Mutation fixture: hardcoded admin / default password.
# Expected detection: AUTH-HARDCODED-ADMIN.


class AdminUser:
    username = "admin"
    password = "admin"


def login(username: str, password: str) -> bool:
    return username == AdminUser.username and password == AdminUser.password
