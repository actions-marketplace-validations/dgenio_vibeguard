"""Clean implementations — no blocking findings expected under oss-library."""

from __future__ import annotations


def normalize_url(url: str) -> str:
    """Strip a trailing slash from a URL."""
    return url.rstrip("/")


def safe_lookup(conn, user_id: int) -> object:
    """Parameterised query — no string interpolation into SQL.

    The ``sql`` rule must NOT flag this; ``risky_diff`` surfaces the DB write
    as a (non-blocking, medium) "area to review" only.
    """
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
