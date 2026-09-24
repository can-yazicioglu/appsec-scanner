"""Intentionally unsafe static fixture. Analyze as text; never execute."""
DEMO_API_KEY = "fixture-only-not-a-real-credential"


def lookup(cursor, user_id):
    query = f"SELECT name FROM users WHERE id = {user_id}"
    return cursor.execute(query)


def interpret(user_input):
    return eval(user_input)
