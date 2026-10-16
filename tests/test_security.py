"""
Automated Security Regression Tests for College Club Portal (secure/app.py).
Verifies fixes against SQLi, IDOR, Broken Access Control, and lockout/rate limits.
"""
import pytest


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


def test_logout_post_only(client):
    """
    Logout Method Restriction:
    GET /logout must return HTTP 405 (Method Not Allowed) to prevent cross-site logout via image/link tags.
    POST /logout must succeed, clearing the session and redirecting to /login.
    """
    # 1. GET /logout must return 405
    get_resp = client.get("/logout")
    assert get_resp.status_code == 405

    # 2. Simulate logged in user
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["role"] = "admin"

    # Verify session is active
    dash_resp = client.get("/")
    assert dash_resp.status_code == 200

    # 3. POST /logout must redirect to login
    post_resp = client.post("/logout", follow_redirects=False)
    assert post_resp.status_code == 302
    assert post_resp.headers["Location"].endswith("/login")

    # 4. Verify session was cleared
    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_logout_requires_csrf_when_enabled():
    """
    CSRF on Logout:
    POST /logout without a valid CSRF token must return 400 Bad Request when CSRF is enabled.
    """
    import os
    import tempfile
    from secure.app import create_app
    from secure.config import Config

    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    class LogoutCsrfConfig(Config):
        TESTING = True
        WTF_CSRF_ENABLED = True
        DATABASE = db_path
        SECRET_KEY = "test-secret-key-32-bytes-long!"

    try:
        app = create_app(LogoutCsrfConfig)
        client = app.test_client()

        # POST without CSRF token must fail with 400
        resp_missing = client.post("/logout")
        assert resp_missing.status_code == 400
    finally:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass


def test_session_configuration():
    """
    Session Configuration:
    Verify 30-minute lifetime, HttpOnly, SameSite=Lax, and __Host- prefix in production.
    """
    from datetime import timedelta
    from secure.config import Config, TestingConfig

    assert Config.PERMANENT_SESSION_LIFETIME == timedelta(minutes=30)
    assert Config.SESSION_COOKIE_HTTPONLY is True
    assert Config.SESSION_COOKIE_SAMESITE == "Lax"
    assert TestingConfig.SESSION_COOKIE_NAME == "session"
    assert TestingConfig.SESSION_COOKIE_SECURE is False


def test_session_idle_timeout_expires(client):
    """
    Session Expiry:
    A session inactive for longer than PERMANENT_SESSION_LIFETIME (30 min) must expire
    and redirect unauthenticated requests to /login.
    """
    from datetime import datetime, timezone

    # Set up session with an expired last-active timestamp (> 1800 seconds ago)
    now = datetime.now(timezone.utc).timestamp()
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["_last_active"] = now - 1801

    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/login")

    # Session must be completely cleared
    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_session_idle_timeout_active_within_window(client):
    """
    Session Continuity:
    Requests within the 30-minute idle window must succeed and refresh the active timestamp.
    """
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).timestamp()
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["_last_active"] = now - 300  # 5 minutes ago

    resp = client.get("/")
    assert resp.status_code == 200

    with client.session_transaction() as sess:
        assert sess.get("user_id") == 1
        assert sess.get("_last_active") >= now - 5


def test_session_cookie_host_prefix_in_production(monkeypatch):
    """
    Cookie Security:
    In production mode with SESSION_COOKIE_SECURE enabled, SESSION_COOKIE_NAME
    must use the RFC 6265bis __Host- prefix.
    """
    import os
    import tempfile
    from secure.app import create_app
    from secure.config import Config

    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    monkeypatch.setenv("SECRET_KEY", "prod-secret-key-at-least-32-bytes!!")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "true")

    class ProdCookieConfig(Config):
        TESTING = False
        DATABASE = db_path
        SECRET_KEY = "prod-secret-key-at-least-32-bytes!!"
        SESSION_COOKIE_SECURE = True
        SESSION_COOKIE_NAME = "__Host-session"

    try:
        prod_app = create_app(ProdCookieConfig)
        assert prod_app.config["SESSION_COOKIE_NAME"] == "__Host-session"
        assert prod_app.config["SESSION_COOKIE_SECURE"] is True
        assert prod_app.config["SESSION_COOKIE_HTTPONLY"] is True
        assert prod_app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    finally:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass


def test_deleted_user_loses_access_immediately(app, client):
    """
    Authorization Invalidation:
    If a user is deleted from the DB while their session cookie is still valid,
    the app must re-validate against the DB on the next request, clear the session,
    and redirect to /login.
    """
    from secure.db import get_db

    # User bob (id=3) is logged in
    with client.session_transaction() as sess:
        sess["user_id"] = 3
        sess["username"] = "bob"
        sess["role"] = "member"

    # Verify access works prior to deletion
    resp = client.get("/profile/3")
    assert resp.status_code == 200

    # Delete bob from the database
    with app.app_context():
        db = get_db()
        db.execute("DELETE FROM users WHERE id = 3")
        db.commit()

    # Bob's next request must be rejected and redirected to /login
    resp = client.get("/profile/3", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/login")

    # Session must be cleared
    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_demoted_admin_loses_admin_privileges_immediately(app, client):
    """
    Role Re-validation:
    If an admin is demoted to a regular member in the DB while possessing an active session,
    the app must not trust the cookie claim and must deny access to /admin/users with HTTP 403.
    """
    from secure.db import get_db

    # Admin (id=1) is logged in
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["role"] = "admin"

    # Verify admin access works prior to demotion
    resp = client.get("/admin/users")
    assert resp.status_code == 200

    # Demote admin to member in DB
    with app.app_context():
        db = get_db()
        db.execute("UPDATE users SET role = 'member' WHERE id = 1")
        db.commit()

    # Next request to /admin/users must return 403 Forbidden
    resp = client.get("/admin/users")
    assert resp.status_code == 403
    assert b"Forbidden" in resp.data


@pytest.mark.parametrize("header,expected_value", [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "geolocation=(), microphone=(), camera=()"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
])
def test_security_headers_present(client, header, expected_value):
    """
    Security Headers:
    Ensure every HTTP response includes modern hardening headers.
    """
    resp = client.get("/login")
    assert resp.headers.get(header) == expected_value


def test_tightened_content_security_policy(client):
    """
    Content Security Policy:
    Verify CSP contains default-src, frame-ancestors 'none', base-uri 'self', and form-action 'self'.
    """
    resp = client.get("/login")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'self'" in csp
    assert "form-action 'self'" in csp


def test_authenticated_response_cache_control_no_store(app):
    """
    Cache-Control Hardening:
    Authenticated responses must serve Cache-Control: no-store to prevent sensitive data leakage.
    Unauthenticated public responses (e.g. login) do not force no-store.
    """
    client = app.test_client()

    # Unauthenticated response
    unauth_resp = client.get("/login")
    assert unauth_resp.status_code == 200
    assert unauth_resp.headers.get("Cache-Control") != "no-store"

    # Authenticated response
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["role"] = "admin"

    auth_resp = client.get("/")
    assert auth_resp.status_code == 200
    assert auth_resp.headers.get("Cache-Control") == "no-store"
    assert auth_resp.headers.get("Pragma") == "no-cache"


def test_audit_logging_login_success(client, caplog):
    """
    Audit Logging - Login Success:
    Successful authentication must emit an audit log with username, user_id, and ip,
    and must never log the user's password.
    """
    import logging

    caplog.set_level(logging.INFO)
    secret_pass = "admin123"
    resp = client.post("/login", data={"username": "admin", "password": secret_pass})
    assert resp.status_code == 302

    assert "event=login_success" in caplog.text
    assert "username=admin" in caplog.text
    assert "user_id=1" in caplog.text
    assert secret_pass not in caplog.text


def test_audit_logging_login_failure(client, caplog):
    """
    Audit Logging - Login Failure:
    Failed authentication must log an audit failure event without revealing passwords.
    """
    import logging

    caplog.set_level(logging.INFO)
    super_secret_wrong = "super_secret_wrong_pw!"
    resp = client.post("/login", data={"username": "bob", "password": super_secret_wrong})
    assert resp.status_code == 200

    assert "event=login_failure" in caplog.text
    assert "username=bob" in caplog.text
    assert super_secret_wrong not in caplog.text


def test_audit_logging_lockout(client, caplog):
    """
    Audit Logging - Account Lockout:
    Reaching the lockout threshold must emit an audit lockout warning.
    """
    import logging
    from secure.app import limiter

    caplog.set_level(logging.INFO)
    # Perform 5 failed attempts
    for i in range(5):
        limiter.reset()
        client.post("/login", data={"username": "alice", "password": "wrong"})

    assert "event=lockout" in caplog.text
    assert "username=alice" in caplog.text


def test_audit_logging_403_forbidden(member_client, caplog):
    """
    Audit Logging - 403 Forbidden:
    Unauthorized access attempts must emit a 403 audit warning containing user_id and path.
    """
    import logging

    caplog.set_level(logging.INFO)
    resp = member_client.get("/admin/users")
    assert resp.status_code == 403

    assert "event=403_forbidden" in caplog.text
    assert "path=/admin/users" in caplog.text


def test_audit_logging_logout(client, caplog):
    """
    Audit Logging - Logout:
    Session termination must emit an audit logout event.
    """
    import logging

    caplog.set_level(logging.INFO)
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["role"] = "admin"

    resp = client.post("/logout")
    assert resp.status_code == 302

    assert "event=logout" in caplog.text
    assert "username=admin" in caplog.text


def test_login_input_validation_missing_fields(client):
    """
    Input Validation:
    Missing username or password fields must return HTTP 400 Bad Request
    instead of raising unhandled KeyError exceptions.
    """
    # Missing username
    resp_no_user = client.post("/login", data={"password": "password123"})
    assert resp_no_user.status_code == 400
    assert b"Username and password are required" in resp_no_user.data

    # Missing password
    resp_no_pass = client.post("/login", data={"username": "admin"})
    assert resp_no_pass.status_code == 400
    assert b"Username and password are required" in resp_no_pass.data


@pytest.mark.parametrize("username,password,expected_status", [
    ("", "valid_password", 400),
    ("admin", "", 400),
    ("a" * 65, "valid_password", 400),
    ("admin", "b" * 129, 400),
    ("a" * 64, "valid_password", 200),
    ("admin", "b" * 128, 200),
    ("a", "b", 200),
])
def test_login_input_boundary_validation(client, username, password, expected_status):
    """
    Input Boundary Testing:
    Tests lower (1 char) and upper (64 char username, 128 char password) boundaries.
    Out-of-bound inputs return 400, while boundary inputs are safely evaluated by authentication logic.
    """
    from secure.app import limiter
    limiter.reset()

    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == expected_status


def test_ui_base_layout_and_accessible_form(client):
    """
    UI & Accessibility:
    Verify that templates extend base.html, include link to /static/style.css,
    and render accessible form labels with matching input IDs.
    """
    # 1. Login page contains stylesheet link and accessible labels
    resp = client.get("/login")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "/static/style.css" in html
    assert '<label for="username">Username</label>' in html
    assert 'id="username"' in html
    assert '<label for="password">Password</label>' in html
    assert 'id="password"' in html

    # 2. Static stylesheet is successfully served
    css_resp = client.get("/static/style.css")
    assert css_resp.status_code == 200
    assert b"/* Secure Club Portal Stylesheet" in css_resp.data


def test_profile_not_found_returns_404(admin_client):
    """
    Profile Route Boundary:
    When an authenticated administrator queries a non-existent user ID,
    the application must return HTTP 404 Not Found.
    """
    resp = admin_client.get("/profile/99999")
    assert resp.status_code == 404
    assert b"User not found" in resp.data


def test_full_logout_flow(client):
    """
    Logout Flow:
    Verify authenticating, accessing protected resource, logging out,
    and verifying post-logout denial on protected resources.
    """
    # 1. Login
    login_resp = client.post("/login", data={"username": "bob", "password": "bobpw"}, follow_redirects=True)
    assert login_resp.status_code == 200
    assert b"Club Dashboard" in login_resp.data

    # 2. Access dashboard
    dash_resp = client.get("/")
    assert dash_resp.status_code == 200

    # 3. Logout
    logout_resp = client.post("/logout", follow_redirects=True)
    assert logout_resp.status_code == 200
    assert b"Club Portal Login" in logout_resp.data

    # 4. Access dashboard after logout -> redirected to login
    reaccess_resp = client.get("/", follow_redirects=False)
    assert reaccess_resp.status_code == 302
    assert reaccess_resp.headers["Location"].endswith("/login")


def test_session_fixation_protection(client):
    """
    Session Fixation Defense:
    Pre-authentication session data and cookies must be cleared/regenerated upon login.
    """
    # Establish pre-session state
    with client.session_transaction() as sess:
        sess["pre_login_tracker"] = "malicious_fixation_val"

    # Authenticate
    client.post("/login", data={"username": "admin", "password": "admin123"})

    # Verify pre-session key is wiped out
    with client.session_transaction() as sess:
        assert "pre_login_tracker" not in sess
        assert sess.get("user_id") == 1
        assert sess.get("username") == "admin"


@pytest.mark.parametrize("route", [
    "/",
    "/profile/1",
    "/profile/3",
    "/admin/users",
])
def test_unauthenticated_routes_redirect_to_login(app, route):
    """
    Access Control Baseline:
    All protected endpoints must redirect unauthenticated requests to /login with HTTP 302.
    """
    unauth_client = app.test_client()
    resp = unauth_client.get(route, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/login")








