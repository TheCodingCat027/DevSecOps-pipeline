"""
app.py — The FIXED version of the demo Flask application.

This version corrects all deliberately planted vulnerabilities:
  V2 fixed: Parameterized queries (no SQL injection)
  V6 fixed: scrypt password hashing (replaces MD5)
  V7 fixed: No debug=True in production

All functional endpoints work identically to the vulnerable version.
"""

import hashlib
import os
import sqlite3

from flask import Flask, g, jsonify, request

from config import DATABASE_PATH, SECRET_KEY

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    """Get or create a SQLite connection for the current request context."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def hash_password(password: str) -> str:
    """
    Hash a password using scrypt (fix for V6).
    Returns a hex string including the salt, encoded as 'salt$hash'.
    """
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + "$" + dk.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored scrypt hash."""
    try:
        salt_hex, dk_hex = stored_hash.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
        return dk.hex() == dk_hex
    except (ValueError, Exception):
        return False


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

    V2 fix: Uses a parameterized query — no SQL injection possible.
    """
    name = request.args.get("name", "")
    db = get_db()
    cursor = db.execute(
        "SELECT id, name, email FROM users WHERE name = ?",
        (name,),
    )
    rows = cursor.fetchall()
    return jsonify([dict(row) for row in rows]), 200


@app.route("/login", methods=["POST"])
def login() -> tuple:
    """
    Login endpoint.

    V6 fix: Uses scrypt for password verification.
    """
    data = request.get_json(force=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    db = get_db()
    cursor = db.execute(
        "SELECT id, name, password_hash FROM users WHERE name = ?",
        (username,),
    )
    user = cursor.fetchone()
    if user and verify_password(password, user["password_hash"]):
        return jsonify({"status": "ok", "user_id": user["id"]}), 200
    return jsonify({"status": "unauthorized"}), 401


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    with app.app_context():
        db = get_db()
        init_db(db)

    # V7 fix: debug mode read from environment variable, not hard-coded True
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="127.0.0.1", port=5000, debug=debug_mode)
