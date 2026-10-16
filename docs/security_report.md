# Security Assessment Report — Club Portal

## Scope
Internal web application for a college club: login, member/admin roles,
event listing, member profiles, admin user management. Testing performed
only against the local instances built for this benchmarking repository.

## Summary
Authentication alone (requiring login) was assumed to equal security in the
original application baseline. Four primary vulnerabilities were identified,
analyzed, and mitigated, addressing fundamental data-access, authentication,
and authorization defects:

| # | Vulnerability | OWASP Category | Severity |
|---|---|---|---|
| 1 | IDOR on `/profile/<id>` | A01: Broken Access Control | High |
| 2 | SQL Injection on `/login` | A03: Injection | Critical |
| 3 | Missing role check on `/admin/users` | A01: Broken Access Control | Critical |
| 4 | Unthrottled Brute-Force & Credential Stuffing | A07: Identification and Authentication Failures | High |

## Root Cause (shared)
The vulnerable build equates **authentication** ("do you have a valid session cookie?")
with **authorization** ("are you allowed to access or mutate this specific resource?").
It also trusts client-supplied parameters without server-side validation and lacks
essential defense-in-depth safeguards (rate limiting, anti-enumeration, CSRF, and security headers).

## Fixes Applied
- **Database & Query Hardening**: Parameterized all SQL statements using SQLite prepared statements, enabled `PRAGMA foreign_keys = ON`, and isolated schemas across test contexts.
- **Role & Authorization Invalidation**: Re-validates user existence and current role from the database on every request via `login_required` and `admin_required` decorators, immediately revoking demoted or deleted accounts.
- **Cryptographic Storage**: Replaced plaintext credentials with one-way salted password hashes (`werkzeug.security`). Passwords are read from environment variables or cryptographically generated at initialization.
- **Information Leakage Prevention**: Redacted password hashes from admin view templates, removed credential hints, and unified login failure responses with timing equalization dummy hashing to prevent username enumeration.
- **Rate Limiting & DoS-Resistant Lockout**: Implemented `Flask-Limiter` (5 req/min/IP) and tracked lockout state per `(username, ip_address)` pair with exponential backoff, preventing cross-IP denial-of-service lockout attacks.
- **CSRF Protection**: Integrated `Flask-WTF` `CSRFProtect` on all mutating routes (`/login`, POST-only `/logout`).
- **Session Hardening**: Enforced 30-minute session lifetimes, server-side idle timeout enforcement, `HttpOnly`, `SameSite=Lax`, and `__Host-` prefixed secure cookies in production.
- **HTTP Security Headers**: Injected `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, `Cross-Origin-Opener-Policy: same-origin`, tightened `Content-Security-Policy`, and served `Cache-Control: no-store` on authenticated views.
- **Input Validation**: Enforced length and type bounds on inputs, returning HTTP 400 Bad Request on missing or malformed inputs without unhandled exceptions.
- **Security Audit Logging**: Integrated structured logging across security events (login success, failure, lockout, 403 forbidden, logout) without recording passwords.

## Verification
- `poc/exploit_demo.sh` asserts that all 3 exploit vectors succeed against `vulnerable/` (port 5000), exiting non-zero on mismatch.
- `poc/verify_fix.sh` asserts that all attacks are rejected against `secure/` (port 5001) with HTTP 200/403 status codes.
- `tests/test_security.py` runs 56 automated pytest regression tests verifying all security features against `secure/`.
- `tests/test_vulnerable.py` verifies that the 3 exploits continue to demonstrate vulnerabilities on `vulnerable/`.
- `bandit -r secure/ -ll` reports 0 medium/high findings.
- `pip-audit` confirms zero vulnerable dependencies.

## Completed Hardening Items
- **Automated Regression Suite**: Expanded pytest suite with >=90% test coverage enforcement on `secure/`.
- **Secret Key & Configuration Management**: Implemented `secure/config.py` with fail-fast enforcement requiring `SECRET_KEY` in production environments.
- **CI/CD Pipeline with Matrix Testing**: Hardened GitHub Actions workflow (`.github/workflows/security-ci.yml`) running across Python 3.10, 3.11, and 3.12 with pinned commit SHAs, concurrency controls, least-privilege permissions, Bandit SAST, Ruff linting, and pip-audit.

## Remaining Limitations & Residual Risks
- **Rate Limit Storage**: By default, `RATELIMIT_STORAGE_URI` uses in-memory tracking (`memory://`). Multi-worker deployments require configuring an external store (e.g. Redis).
- **Database Engine**: Single SQLite database file imposes write-concurrency limits compared to client-server RDBMS (e.g. PostgreSQL).
- **Authentication Scope**: Multi-Factor Authentication (MFA) and self-service password recovery workflows are not implemented in this educational lab.
