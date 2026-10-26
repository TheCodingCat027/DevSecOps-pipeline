"""
Tests for the VULNERABLE demo app.

These tests verify functional correctness only — they test what the app does,
not whether it is secure. The FIXED app must pass these same tests, proving
that the security fixes are non-breaking.

Note: We use an in-memory SQLite database for tests.
"""

import hashlib
import sqlite3
import sys
from pathlib import Path

import pytest

# Add the vulnerable app directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import app, init_db  # noqa: E402


@pytest.fixture
def client(tmp_path):
    """Create a test Flask client with an isolated database."""
    db_path = str(tmp_path / "test.db")
    app.config["TESTING"] = True
    app.config["DATABASE_PATH"] = db_path

    # Patch the DATABASE_PATH in the app's config module
    import config  # noqa: PLC0415
    original_db = config.DATABASE_PATH
    config.DATABASE_PATH = db_path

    # Also patch the import in app.py
    import app as app_module  # noqa: PLC0415
    app_module.DATABASE_PATH = db_path

    with app.test_client() as client:
        with app.app_context():
            # Use the real DATABASE_PATH from config
            import importlib  # noqa: PLC0415
            import app as app_mod  # noqa: PLC0415, F811
            # Create a db at the tmp path
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            init_db(conn)
            # Seed a user with MD5 hash (vulnerable app uses MD5)
            password_hash = hashlib.md5(b"testpassword").hexdigest()
            conn.execute(
                "INSERT INTO users (name, password_hash, email) VALUES (?, ?, ?)",
                ("alice", password_hash, "alice@example.com"),
            )
            conn.commit()
            conn.close()
        yield client

    config.DATABASE_PATH = original_db


def test_health_endpoint(client):
    """Health endpoint should return 200 and status ok."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"


def test_login_success(client):
    """Login with correct credentials should return 200."""
    response = client.post(
        "/login",
        json={"username": "alice", "password": "testpassword"},
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"


def test_login_failure(client):
    """Login with wrong credentials should return 401."""
    response = client.post(
        "/login",
        json={"username": "alice", "password": "wrongpassword"},
    )
    assert response.status_code == 401
    data = response.get_json()
    assert data["status"] == "unauthorized"


def test_search_users_returns_results(client):
    """Users search should return matching users."""
    response = client.get("/users?name=alice")
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["name"] == "alice"


def test_search_users_no_results(client):
    """Users search for a non-existent name should return empty list."""
    response = client.get("/users?name=nobody")
    assert response.status_code == 200
    data = response.get_json()
    assert data == []
