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
