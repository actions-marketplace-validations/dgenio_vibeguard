# PR: "add bulk price update for the sale"
# What the AI did: built the UPDATE with an f-string straight from request
# input and shipped no accompanying test.
import sqlite3


def bump_prices(conn: sqlite3.Connection, category: str, pct: float) -> None:
    # f-string interpolation straight into SQL — classic injection vector
    query = f"UPDATE products SET price = price * {pct} WHERE category = '{category}'"
    conn.execute(query)


def delete_category(conn: sqlite3.Connection, category: str) -> None:
    conn.execute("DELETE FROM products WHERE category = '" + category + "'")
