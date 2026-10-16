# Vulnerability Documentation

## 1. Insecure Direct Object Reference (IDOR) — Broken Access Control
**Location:** `vulnerable/app.py`, route `/profile/<int:user_id>`

**Root cause:** The route trusts the `user_id` from the URL without checking
whether the logged-in session user is allowed to view that profile. The only
gate is "are you logged in at all" — not "is this *your* data."

**Impact:** Any authenticated member (even the lowest-privilege account) can
enumerate `/profile/1`, `/profile/2`, `/profile/3`... and read every other
user's full name, email, phone number, and role.

**Fix (secure/app.py):** Added an authorization check —
`session["user_id"] != user_id and session["role"] != "admin"` → `403`.
Users may only view their own profile unless they are an admin.

---

## 2. SQL Injection
**Location:** `vulnerable/app.py`, route `/login`

**Root cause:** The login query is built via raw string concatenation:
```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

**Impact:** An attacker can submit `username = admin' --` to comment out the
password check and log in as admin with no valid password. Could also be
used to exfiltrate data via UNION-based injection.

**Fix (secure/app.py):** Replaced with a parameterized query
(`db.execute("SELECT * FROM users WHERE username = ?", (username,))`) and
added password hashing (`werkzeug.security.generate_password_hash` /
`check_password_hash`) so even DB access alone doesn't leak usable passwords.

---

## 3. Broken Access Control — Admin Panel
**Location:** `vulnerable/app.py`, route `/admin/users`

**Root cause:** The route only checks `"user_id" in session` (i.e., "are you
logged in"), not `session["role"] == "admin"`. The admin link is merely
omitted from the member's dashboard UI — "security through hiding the
button" — but the URL itself has no server-side protection.

**Impact:** Any member who guesses or is told the URL `/admin/users` can
view the entire user table, including plaintext passwords in the vulnerable
build.

**Fix (secure/app.py):** Added an `@admin_required` decorator that checks
`session["role"] == "admin"` server-side and returns `403` otherwise. Also
stopped returning password hashes in the admin view entirely (defense in
depth / least privilege on data exposure).

---

## 4. Unthrottled Brute-Force & Credential Stuffing
**Location:** `vulnerable/app.py`, route `/login`

**Root cause:** The endpoint accepts infinite sequential login attempts per IP
and per user account with no rate limits, delay, or lockout mechanism.

**Impact:** An attacker can perform automated high-speed dictionary attacks or
credential stuffing against known usernames until valid passwords are breached.

**Fix (secure/app.py):** Implemented a defense-in-depth throttling architecture:
1. `Flask-Limiter` throttling at 5 requests/minute per IP address returning `429 Too Many Requests`.
2. DoS-resistant lockout mechanism tracked per `(username, ip_address)` pair with exponential backoff (starting at 5 minutes after 5 consecutive failures), preventing attackers from locking out legitimate users across other IPs.
3. Timing equalization dummy hash and uniform error messages (`Invalid credentials`) to prevent username enumeration.
