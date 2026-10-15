# Security Assessment Report — Club Portal

## Scope
Internal web application for a college club: login, member/admin roles,
event listing, member profiles, admin user management. Testing performed
only against the local instance built for this assignment.

## Summary
Authentication alone (requiring login) was assumed to equal security. It
does not. Three vulnerabilities were found and fixed, all stemming from the
same root issue: **missing server-side authorization checks** beyond "is
this user logged in."

| # | Vulnerability | OWASP Category | Severity |
|---|---|---|---|
| 1 | IDOR on `/profile/<id>` | A01: Broken Access Control | High |
| 2 | SQL Injection on `/login` | A03: Injection | Critical |
| 3 | Missing role check on `/admin/users` | A01: Broken Access Control | Critical |

## Root Cause (shared)
The vulnerable build equates **authentication** ("do you have a valid
session?") with **authorization** ("are you allowed to see/do this specific
thing?"). It also trusts client-supplied input (URL IDs, form fields)
without validation at the data-access layer.

## Fixes Applied
- Parameterized all SQL queries (no string concatenation).
- Added explicit ownership/role checks (`login_required`, `admin_required`
  decorators) on every sensitive route.
- Hashed passwords with `werkzeug.security` instead of storing plaintext.
- Removed sensitive fields (password hash) from admin API response data.
- Added baseline security headers (`X-Content-Type-Options`,
  `X-Frame-Options`, `Content-Security-Policy`) and `HttpOnly`/`SameSite`
  session cookies.

## Verification
`poc/exploit_demo.sh` demonstrates all 3 attacks succeeding against
`vulnerable/` (port 5000). `poc/verify_fix.sh` runs the same requests
against `secure/` (port 5001) and shows them blocked (403 / failed login).

## Assumptions & Scope
- Single SQLite file, no network exposure beyond localhost.
- Session management uses Flask's signed cookie sessions (not a full
  server-side session store).
- No rate limiting / account lockout implemented in this pass (listed as
  bonus scope).

## Remaining Limitations
- `SECRET_KEY` should come from an environment variable / secrets manager
  in any real deployment, not a hardcoded default.
- `SESSION_COOKIE_SECURE` should be enabled once served over HTTPS.
- No CSRF tokens on forms yet (would be needed before any production use).
- No automated regression test suite included (bonus item, not implemented
  in this pass).
- No rate limiting/lockout on `/login` (bonus item, not implemented).
