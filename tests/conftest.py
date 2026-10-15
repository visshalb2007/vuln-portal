import os
import sys
import tempfile
import pytest

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from secure.app import app as secure_app, init_db, limiter


@pytest.fixture(autouse=True)
def reset_limiter_fixture():
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture
def app():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    secure_app.config.update({
        "TESTING": True,
        "DATABASE": db_path,
        "SECRET_KEY": "test-secret-key-32-bytes-long!",
        "RATELIMIT_STORAGE_URI": "memory://",
    })

    with secure_app.app_context():
        init_db(db_path)

    yield secure_app

    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def member_client(client):
    """Client authenticated as standard member (bob, id=3)."""
    with client.session_transaction() as sess:
        sess["user_id"] = 3
        sess["role"] = "member"
    return client


@pytest.fixture
def admin_client(client):
    """Client authenticated as administrator (admin, id=1)."""
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["role"] = "admin"
    return client
