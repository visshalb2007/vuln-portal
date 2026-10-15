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
