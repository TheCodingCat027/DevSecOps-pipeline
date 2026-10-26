"""
app.py — The VULNERABLE version of the demo Flask application.

⚠️  WARNING: THIS APPLICATION IS INTENTIONALLY INSECURE FOR EDUCATIONAL PURPOSES.
⚠️  It contains deliberately planted security flaws. DO NOT DEPLOY OR EXPOSE TO A NETWORK.
⚠️  See demo-app/README.md for full safety warnings.

Planted vulnerabilities (see demo-app/seeded-vulnerabilities.md for ground truth):
  V2  (line ~36): SQL injection via string concatenation in /users endpoint
  V6  (line ~52): Weak password hashing using MD5
  V7  (line ~66): Flask debug mode enabled (debug=True)
"""

import hashlib  # V6: used for MD5 hashing (intentionally weak)
import sqlite3

from flask import Flask, g, jsonify, request

from config import DATABASE_PATH

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key-not-for-production"  # noqa: S105


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    """Get or create a SQLite connection for the current request context."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db(db: sqlite3.Connection) -> None:
    """Initialize the database schema."""
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL
        )
        """
    )
    db.commit()


@app.teardown_appcontext
def close_db(exc: Exception | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/health")
def health() -> tuple:
    """Health check endpoint."""
    return jsonify({"status": "ok"}), 200


@app.route("/users")
def search_users() -> tuple:
    """
    Search users by name.

    V2 — SQL INJECTION: user input is concatenated directly into the SQL query.
    An attacker can inject malicious SQL via the 'name' query parameter.
    Example exploit: ?name=' OR '1'='1
    Expected detecting tool: Semgrep (rule: python.lang.security.audit.sqli.formatted-sql-query)
    """
    name = request.args.get("name", "")
    db = get_db()
    # V2: SQL injection vulnerability — string concatenation into SQL query (line 36 is the key line)
    query = "SELECT id, name, email FROM users WHERE name = '" + name + "'"  # noqa: S608 — intentional
    cursor = db.execute(query)  # nosec — intentional vulnerability for scanner demo
    rows = cursor.fetchall()
    return jsonify([dict(row) for row in rows]), 200


@app.route("/login", methods=["POST"])
def login() -> tuple:
    """
    Login endpoint.

    V6 — WEAK HASHING: MD5 is used to hash the password before comparison.
    MD5 is cryptographically broken; passwords can be reversed with rainbow tables.
    Expected detecting tool: Semgrep (rule: python.lang.security.audit.md5-used-as-password)
    """
    data = request.get_json(force=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # V6: MD5 used as password hash — intentionally weak (line 52 is the hash line)
    password_hash = hashlib.md5(password.encode()).hexdigest()  # noqa: S324 — intentional

    db = get_db()
    cursor = db.execute(
        "SELECT id, name FROM users WHERE name = ? AND password_hash = ?",
        (username, password_hash),
    )
    user = cursor.fetchone()
    if user:
        return jsonify({"status": "ok", "user_id": user["id"]}), 200
    return jsonify({"status": "unauthorized"}), 401


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os

    with app.app_context():
        db = get_db()
        init_db(db)

    # V7 — Flask debug mode: debug=True exposes the interactive debugger to all clients
    # Expected detecting tool: Semgrep (rule: python.flask.security.audit.app-run-debug-enabled)
    app.run(host="127.0.0.1", port=5000, debug=True)  # noqa: S201 — intentional
