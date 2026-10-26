"""
Tests for the FIXED demo app.

These are the same functional tests as the vulnerable app.
The fixed app must pass all of them, proving that security fixes are non-breaking.
"""

import os
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

# Set required env vars before importing config
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-testing-only")
os.environ.setdefault("DATABASE_PATH", ":memory:")

from app import app, hash_password, init_db  # noqa: E402


@pytest.fixture
def client(tmp_path):
    """Create a test Flask client with an isolated database."""
    db_path = str(tmp_path / "test.db")
    os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"
    os.environ["DATABASE_PATH"] = db_path

    import config  # noqa: PLC0415
    import importlib  # noqa: PLC0415
    config.DATABASE_PATH = db_path
    config.SECRET_KEY = "test-secret-key-for-testing-only"

    import app as app_module  # noqa: PLC0415
    app_module.DATABASE_PATH = db_path
    app_module.app.config["SECRET_KEY"] = "test-secret-key-for-testing-only"

    with app_module.app.test_client() as client:
        with app_module.app.app_context():
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            init_db(conn)
            # Seed a user with scrypt hash (fixed app uses scrypt)
            password_hash = hash_password("testpassword")
            conn.execute(
                "INSERT INTO users (name, password_hash, email) VALUES (?, ?, ?)",
                ("alice", password_hash, "alice@example.com"),
            )
            conn.commit()
            conn.close()
        yield client


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
