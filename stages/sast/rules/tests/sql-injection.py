# Semgrep rule tests for devsecops-python-sql-injection-string-built-query
# Run with: semgrep --test --config stages/sast/rules stages/sast/rules/tests
import sqlite3


def positives(db, cursor, name, uid):
    # ruleid: devsecops-python-sql-injection-string-built-query
    db.execute("SELECT id FROM users WHERE name = '" + name + "'")

    # ruleid: devsecops-python-sql-injection-string-built-query
    cursor.execute(f"SELECT id FROM users WHERE id = {uid}")

    # ruleid: devsecops-python-sql-injection-string-built-query
    cursor.execute("SELECT id FROM users WHERE name = '{}'".format(name))

    # ruleid: devsecops-python-sql-injection-string-built-query
    cursor.execute("SELECT id FROM users WHERE name = '%s'" % name)

    # two-step: the query is built first and executed later
    query = "SELECT id, name FROM users WHERE name = '" + name + "'"
    # ruleid: devsecops-python-sql-injection-string-built-query
    cur = db.execute(query)

    # ruleid: devsecops-python-sql-injection-string-built-query
    db.executescript("DELETE FROM users WHERE name = '" + name + "'")


def positive_sqlite3_connection(name):
    conn = sqlite3.connect("x.db")
    # ruleid: devsecops-python-sql-injection-string-built-query
    return conn.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall()


def negatives(db, cursor, name, uid):
    # ok: devsecops-python-sql-injection-string-built-query
    db.execute("SELECT id FROM users WHERE name = ?", (name,))

    # ok: devsecops-python-sql-injection-string-built-query
    cursor.execute("SELECT id FROM users WHERE name = %s", (name,))

    # ok: devsecops-python-sql-injection-string-built-query
    cursor.execute("SELECT id FROM users WHERE name = :name", {"name": name})

    # ok: devsecops-python-sql-injection-string-built-query
    cursor.execute("SELECT id FROM users")

    constant = "SELECT id FROM " + "users"
    # ok: devsecops-python-sql-injection-string-built-query
    cursor.execute(constant)

    # the values travel as parameters; the f-string has no interpolation
    # ok: devsecops-python-sql-injection-string-built-query
    cursor.execute(f"SELECT id FROM users", (uid,))
