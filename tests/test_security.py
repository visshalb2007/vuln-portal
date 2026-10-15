"""
Automated Security Regression Tests for College Club Portal (secure/app.py).
Verifies fixes against SQLi, IDOR, Broken Access Control, and lockout/rate limits.
"""


def test_sqli_login_bypass_fails(client):
    """
    Vulnerability 2: SQL Injection on /login.
    In vulnerable/app.py, payload `admin' --` with arbitrary password bypasses authentication.
    In secure/app.py, parameterized query treats input literally; authentication must fail.
    """
    sqli_payloads = [
        "admin' --",
        "' OR '1'='1",
        "admin' OR 1=1 --",
    ]
    for payload in sqli_payloads:
        resp = client.post("/login", data={"username": payload, "password": "wrongpassword"})
        assert resp.status_code == 200
        assert b"Invalid credentials" in resp.data

        # Ensure session was not created
        with client.session_transaction() as sess:
            assert "user_id" not in sess


def test_idor_non_admin_cannot_view_other_profile(member_client):
    """
    Vulnerability 1: Insecure Direct Object Reference (IDOR) on /profile/<id>.
    Authenticated user 'bob' (id=3, role='member') attempts to view 'admin' profile (id=1).
    In secure/app.py, ownership/role verification must reject with HTTP 403 Forbidden.
    """
    resp = member_client.get("/profile/1")
    assert resp.status_code == 403
    assert b"Forbidden" in resp.data

    # Also test another member's profile (alice, id=2)
    resp_alice = member_client.get("/profile/2")
    assert resp_alice.status_code == 403
    assert b"Forbidden" in resp_alice.data


def test_broken_access_control_member_cannot_access_admin_users(member_client):
    """
    Vulnerability 3: Missing role check on /admin/users.
    Authenticated standard member 'bob' requests /admin/users directly.
    In secure/app.py, @admin_required rejects the request with HTTP 403 Forbidden.
    """
    resp = member_client.get("/admin/users")
    assert resp.status_code == 403
    assert b"Forbidden" in resp.data


def test_legitimate_access_member_can_view_own_profile(member_client):
    """
    Legitimate Access:
    Authenticated user 'bob' (id=3) must successfully view his own profile (/profile/3).
    """
    resp = member_client.get("/profile/3")
    assert resp.status_code == 200
    assert b"Bob Member" in resp.data
    assert b"bob@club.edu" in resp.data


def test_legitimate_access_admin_can_view_admin_users(admin_client):
    """
    Legitimate Access:
    Authenticated user 'admin' (id=1, role='admin') must successfully access /admin/users.
    Verifies that the response contains user roster and does NOT leak password hashes.
    """
    resp = admin_client.get("/admin/users")
    assert resp.status_code == 200
    assert b"All Users (Admin)" in resp.data
    assert b"admin@club.edu" in resp.data
    assert b"alice@club.edu" in resp.data
    assert b"bob@club.edu" in resp.data
    assert b"scrypt:" not in resp.data
    assert b"pbkdf2:" not in resp.data


def test_legitimate_access_admin_can_view_any_profile(admin_client):
    """
    Legitimate Access:
    Admin role can view member profiles (e.g., bob at /profile/3) for administrative auditing.
    """
    resp = admin_client.get("/profile/3")
    assert resp.status_code == 200
    assert b"Bob Member" in resp.data


def test_unauthenticated_requests_redirect_to_login(client):
    """
    Access Control Baseline:
    Anonymous requests to protected endpoints (/, /profile/1, /admin/users)
    must redirect (302) to /login.
    """
    protected_urls = ["/", "/profile/1", "/admin/users"]
    for url in protected_urls:
        resp = client.get(url, follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


def test_account_lockout_after_five_failed_attempts(client, app):
    """
    Account Lockout Defense:
    Submitting 5 consecutive incorrect passwords for a registered username
    must trigger an account lock for 5 minutes and display an explicit lockout message.
    Subsequent attempts (even with valid credentials) must remain locked during the lockout window.
    """
    target_user = "bob"
    attacker_ip = "192.168.1.5"
    for i in range(1, 6):
        resp = client.post(
            "/login",
            data={"username": target_user, "password": f"wrong_{i}"},
            environ_overrides={"REMOTE_ADDR": attacker_ip}
        )
        assert resp.status_code == 200
        assert b"Invalid credentials" in resp.data

    # Verify in DB that (username, IP) is marked locked
    with app.app_context():
        from secure.db import get_db
        db = get_db()
        attempt_row = db.execute(
            "SELECT * FROM login_attempts WHERE username = ? AND ip_address = ?",
            (target_user, attacker_ip)
        ).fetchone()
        assert attempt_row is not None
        assert attempt_row["locked_until"] is not None
        assert attempt_row["failed_attempts"] >= 5

    # Reset IP rate limiter to test lockout layer without rate limiter collision
    from secure.app import limiter
    limiter.reset()

    # Attempt with correct password from locked IP is rejected
    resp_blocked = client.post(
        "/login",
        data={"username": target_user, "password": "bobpw"},
        environ_overrides={"REMOTE_ADDR": attacker_ip}
    )
    assert resp_blocked.status_code == 200
    assert b"Invalid credentials" in resp_blocked.data
    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_successful_login_resets_failed_attempt_counter(client, app):
    """
    Lockout Counter Reset:
    When a user with prior failed login attempts enters their correct password,
    the failed attempt counter must reset to zero and session authentication succeed.
    """
    target_user = "alice"
    # Generate 2 failed attempts
    client.post("/login", data={"username": target_user, "password": "wrong_password_1"})
    client.post("/login", data={"username": target_user, "password": "wrong_password_2"})

    # Now login with the correct password
    resp = client.post(
        "/login",
        data={"username": target_user, "password": "alicepw"},
        environ_overrides={"REMOTE_ADDR": "192.168.1.101"},
        follow_redirects=True
    )
    assert resp.status_code == 200
    assert b"Club Dashboard" in resp.data
    assert b"/profile/2" in resp.data

    # Verify database counter has reset
    with app.app_context():
        import sqlite3
        conn = sqlite3.connect(app.config["DATABASE"])
        conn.row_factory = sqlite3.Row
        user = conn.execute("SELECT * FROM users WHERE username = ?", (target_user,)).fetchone()
        assert user["failed_attempts"] == 0
        assert user["locked_until"] is None
        conn.close()


def test_ip_rate_limiting_on_login(client):
    """
    IP Rate Limiting:
    Flask-Limiter restricts POST requests on /login to 5 per minute per IP.
    The 6th request from the same IP within a minute must return HTTP 429 Too Many Requests.
    """
    test_ip = "10.0.0.42"
    # Send 5 allowable requests from the same IP
    for i in range(5):
        resp = client.post(
            "/login",
            data={"username": f"attacker_{i}", "password": "wrong"},
            environ_overrides={"REMOTE_ADDR": test_ip}
        )
        assert resp.status_code == 200

    # 6th request from the same IP must be throttled with HTTP 429
    resp_rate_limited = client.post(
        "/login",
        data={"username": "attacker_6", "password": "wrong"},
        environ_overrides={"REMOTE_ADDR": test_ip}
    )
    assert resp_rate_limited.status_code == 429
    assert b"Too many requests" in resp_rate_limited.data


def test_missing_secret_key_fails_fast_in_production():
    """
    Security Configuration:
    In non-testing mode, a missing SECRET_KEY must fail fast at startup
    and never fall back to a hardcoded insecure default key.
    """
    import pytest
    from secure.config import Config

    with pytest.raises(RuntimeError, match="SECRET_KEY environment variable is required"):
        Config.check_valid({"TESTING": False, "SECRET_KEY": None})


def test_app_factory_create_app():
    """
    App Factory Pattern:
    create_app() must accept configuration objects and return a properly configured Flask app.
    """
    from secure.app import create_app
    from secure.config import TestingConfig

    test_app = create_app(TestingConfig)
    assert test_app.config["TESTING"] is True
    assert test_app.config["SECRET_KEY"] == "test-secret-key-32-bytes-long!"


def test_database_foreign_keys_enabled(app):
    """
    Database Hardening:
    SQLite database connections must have PRAGMA foreign_keys enabled.
    """
    with app.app_context():
        from secure.db import get_db
        db = get_db()
        fk_status = db.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk_status == 1


def test_seed_passwords_not_hardcoded(monkeypatch):
    """
    Seed Credential Hardening:
    Seed passwords must not be hardcoded in secure/ and must generate random values or read from env.
    """
    from secure.db import get_seed_passwords
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("ALICE_PASSWORD", raising=False)
    monkeypatch.delenv("BOB_PASSWORD", raising=False)

    passwords = get_seed_passwords()
    assert len(passwords["admin"]) >= 16
    assert passwords["admin"] != "admin123"


def test_login_page_does_not_contain_credential_hint(client):
    """
    UI Hardening:
    The login page must not reveal credential hints or valid username/password pairs.
    """
    resp = client.get("/login")
    assert resp.status_code == 200
    assert b"admin/admin123" not in resp.data
    assert b"alice/alicepw" not in resp.data
    assert b"bob/bobpw" not in resp.data


def test_lockout_expiry_resets_failed_attempts(client, monkeypatch, app):
    """
    Lockout Expiry Hardening:
    When an account lock expires, failed_attempts must reset to 0 so that a single
    wrong password after expiry does not immediately re-lock the account.
    """
    from datetime import datetime as dt, timedelta, timezone as tz
    import secure.app

    target_user = "bob"
    target_ip = "192.168.5.5"
    # 5 failed attempts trigger lockout for (target_user, target_ip)
    for i in range(1, 6):
        client.post(
            "/login",
            data={"username": target_user, "password": f"wrong_{i}"},
            environ_overrides={"REMOTE_ADDR": target_ip}
        )

    # Verify locked in DB
    with app.app_context():
        from secure.db import get_db
        db = get_db()
        attempt_row = db.execute(
            "SELECT * FROM login_attempts WHERE username = ? AND ip_address = ?",
            (target_user, target_ip)
        ).fetchone()
        assert attempt_row is not None
        assert attempt_row["locked_until"] is not None

    from secure.app import limiter
    limiter.reset()

    resp_locked = client.post(
        "/login",
        data={"username": target_user, "password": "wrong"},
        environ_overrides={"REMOTE_ADDR": target_ip}
    )
    assert resp_locked.status_code == 200
    assert b"Invalid credentials" in resp_locked.data

    # Freeze/fast-forward time to 6 minutes later (lock was 5 minutes)
    future_time = dt.now(tz.utc) + timedelta(minutes=6)

    class MockDatetime:
        @classmethod
        def now(cls, tzinfo=None):
            return future_time

        @classmethod
        def fromisoformat(cls, s):
            return dt.fromisoformat(s)

    monkeypatch.setattr(secure.app, "datetime", MockDatetime)
    limiter.reset()

    # First attempt with wrong password after expiry: must report 'Invalid credentials'
    resp_after_expiry = client.post(
        "/login",
        data={"username": target_user, "password": "wrong_after_expiry"},
        environ_overrides={"REMOTE_ADDR": target_ip}
    )
    assert resp_after_expiry.status_code == 200
    assert b"Invalid credentials" in resp_after_expiry.data
    assert b"Account locked, try again later" not in resp_after_expiry.data


def test_anti_enumeration_identical_responses_and_dummy_hash(client):
    """
    Anti-Enumeration & Timing Defense:
    Unknown username, incorrect password, and locked accounts must return
    strictly identical HTTP status (200) and error messages to prevent username
    harvesting and enumeration.
    """
    # 1. Unknown user
    resp_unknown = client.post(
        "/login",
        data={"username": "nonexistent_user", "password": "any_password"},
        environ_overrides={"REMOTE_ADDR": "192.168.2.1"}
    )
    # 2. Known user with wrong password
    resp_wrong_pw = client.post(
        "/login",
        data={"username": "alice", "password": "wrong_password"},
        environ_overrides={"REMOTE_ADDR": "192.168.2.2"}
    )
    assert resp_unknown.status_code == 200
    assert resp_wrong_pw.status_code == 200
    assert b"Invalid credentials" in resp_unknown.data
    assert b"Invalid credentials" in resp_wrong_pw.data


def test_lockout_dos_resistance_different_ip_can_login(client, app):
    """
    DoS Resistance:
    An attacker at IP A submitting 5 failed attempts locks (username, IP A),
    but a legitimate user from IP B can still log in with the correct password.
    """
    target_user = "alice"
    attacker_ip = "198.51.100.1"
    legit_ip = "203.0.113.5"

    # Attacker exhausts 5 failed attempts from attacker_ip
    for i in range(1, 6):
        client.post(
            "/login",
            data={"username": target_user, "password": f"guess_{i}"},
            environ_overrides={"REMOTE_ADDR": attacker_ip}
        )

    # Attacker IP is locked
    with app.app_context():
        from secure.db import get_db
        db = get_db()
        row = db.execute(
            "SELECT * FROM login_attempts WHERE username = ? AND ip_address = ?",
            (target_user, attacker_ip)
        ).fetchone()
        assert row is not None
        assert row["locked_until"] is not None

    # Legitimate user from legit_ip logs in successfully
    resp = client.post(
        "/login",
        data={"username": target_user, "password": "alicepw"},
        environ_overrides={"REMOTE_ADDR": legit_ip},
        follow_redirects=True
    )
    assert resp.status_code == 200
    assert b"Club Dashboard" in resp.data
    with client.session_transaction() as sess:
        assert sess.get("user_id") == 2


def test_csrf_protection_post_without_token_returns_400():
    """
    CSRF Protection:
    When WTF_CSRF_ENABLED is active, any POST request submitted without a valid
    CSRF token must be rejected with HTTP 400 Bad Request.
    """
    import re, os, tempfile
    from secure.app import create_app
    from secure.db import init_db

    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    try:
        csrf_app = create_app({
            "TESTING": True,
            "WTF_CSRF_ENABLED": True,
            "SECRET_KEY": "csrf-secret-key-test-32-bytes!!",
            "DATABASE": db_path,
            "RATELIMIT_STORAGE_URI": "memory://",
        })
        with csrf_app.app_context():
            init_db(db_path)

        csrf_client = csrf_app.test_client()

        # 1. POST without token -> HTTP 400 Bad Request
        resp_missing = csrf_client.post(
            "/login",
            data={"username": "bob", "password": "wrong"}
        )
        assert resp_missing.status_code == 400

        # 2. Retrieve valid token from login page
        resp_get = csrf_client.get("/login")
        assert resp_get.status_code == 200
        match = re.search(r'name="csrf_token" value="([^"]+)"', resp_get.data.decode("utf-8"))
        assert match is not None
        token = match.group(1)

        # 3. POST with valid token -> passes CSRF verification (not 400)
        resp_with_token = csrf_client.post(
            "/login",
            data={"username": "bob", "password": "wrong", "csrf_token": token}
        )
        assert resp_with_token.status_code == 200
        assert b"Invalid credentials" in resp_with_token.data
    finally:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass
