# Threat Model — College Club Portal ("Trust Issues")

## System Overview & Architecture
The College Club Portal is a lightweight web application built on Flask with SQLite. It serves authenticated members and administrators, allowing members to access upcoming club events and view profile data, while granting administrators administrative user visibility.

```
+--------------------------------------------------------------------------------+
|                             UNTRUSTED NETWORK / BROWSER                        |
+--------------------------------------------------------------------------------+
             |                                    |                        |
             | 1. Anonymous Requests              | 2. Member Session      | 3. Admin Session
             v                                    v                        v
+--------------------------------------------------------------------------------+
| TRUST BOUNDARY: Application Edge (HTTP / TLS)                                  |
+--------------------------------------------------------------------------------+
             |                                    |                        |
             +------------------+-----------------+------------------------+
                                |
                                v
                   +---------------------------+
                   |  Flask Application Server |
                   |  (Routing & Session Auth) |
                   +---------------------------+
                                |
             +------------------+------------------+
             |                                     |
             v                                     v
+-------------------------+             +----------------------+
| SQLite Database         |             | Client Session Store |
| (Users, Events, Hashes) |             | (Signed Cookie)      |
+-------------------------+             +----------------------+
```

## Assets & Classification

| Asset | Description | Sensitivity | Security Objectives |
|-------|-------------|-------------|---------------------|
| **User Credentials** | Plaintext passwords, authentication hashes (`werkzeug.security`) stored in `users.password`. | Critical | Confidentiality, Integrity (protect from SQLi exfiltration, weak hashing, and credential stuffing). |
| **Session Tokens** | Cryptographically signed client session cookies (`session['user_id']`, `session['role']`). | High | Integrity, Confidentiality (prevent token tampering, session fixation, and XSS extraction). |
| **Profile PII** | Member personal details: `full_name`, `email`, `phone`, club participation record. | High | Confidentiality (prevent unauthorized horizontal disclosure via IDOR). |
| **Admin Panel & Data** | System-wide user roster (`/admin/users`), user administrative metadata, membership lists. | High | Integrity, Availability, Confidentiality (prevent vertical privilege escalation). |


## Threat Actors & Motivations

```
                                  [ Threat Actors ]
                                          |
       +--------------------+-------------+-------------+---------------------+
       |                    |                           |                     |
       v                    v                           v                     v
[ Anonymous Visitor ]  [ Authenticated Member ]   [ Malicious Insider ]  [ Authenticated Admin ]
- Unauthenticated      - Valid member creds       - Legitimate user/dev  - Full portal control
- Seeks entry / auth   - Horizontal IDOR target   - Bypasses operational - Compromised admin
  bypass & enumeration - Seeks privilege escal.     controls / abuses data  or malicious admin
```

### 1. Anonymous Visitor (Unauthenticated External Attacker)
- **Privilege Level**: None.
- **Capabilities**: Can submit arbitrary HTTP requests, query public endpoints (`/login`), inspect returned HTTP headers, cookies, and attempt brute-force, injection, or CSRF payloads against authentication interfaces.
- **Goals**: Bypass authentication, gain entry to member or admin dashboards, steal credentials, discover hidden administrative routes.

### 2. Authenticated Member (Standard User)
- **Privilege Level**: Role `member` (e.g., `alice`, `bob`).
- **Capabilities**: Can access personal profile (`/profile/<own_id>`) and club dashboard (`/`).
- **Goals**: Horizontal privilege escalation (accessing other members' private profiles/PII) or vertical privilege escalation (accessing `/admin/users` and club user rosters).

### 3. Authenticated Admin (Privileged User)
- **Privilege Level**: Role `admin`.
- **Capabilities**: Access to all endpoints, including member directory and management panels.
- **Goals / Risks**: Account compromise via session hijacking or weak passwords, leading to total compromise of all portal data and membership records.

### 4. Malicious Insider (Authorized User with Host / Network Access)
- **Privilege Level**: Local network participant, shared device user, or club officer.
- **Capabilities**: Direct access to local storage, network traffic snooping on unencrypted HTTP, or exploitation of unvalidated session tokens and missing audit logging.
- **Goals**: Exfiltrate user hashes, tamper with database records, harvest PII at rest.


## Attack Surfaces

```
+---------------------------------------------------------------------------------------+
| Route / Surface          | Method     | Auth State        | Key Threat Vectors         |
+--------------------------+------------+-------------------+---------------------------+
| /login                   | GET, POST  | Anonymous         | SQLi, brute-force, lockout |
| /logout                  | POST       | Authenticated     | Cross-site logout, CSRF   |
| /profile/<int:user_id>   | GET        | Authenticated     | IDOR, PII leakage         |
| /admin/users             | GET        | Member or Admin   | Broken access control      |
| Session Cookie           | Client-side| All sessions      | Tampering, XSS hijacking  |
+---------------------------------------------------------------------------------------+
```

### 1. Login Form (`/login` — POST)
- **Entry Point**: Form inputs (`username`, `password`, `csrf_token`).
- **Data Flow**: Untrusted string input received by Flask, validated for length/type, and evaluated via parameterized query.
- **Threat Vector**: SQL injection via unescaped string formatting, automated credential stuffing, username enumeration, and lockout DoS attacks.
- **Trust Boundary**: Crossing from untrusted public web client into application server and SQLite database.

### 2. Logout Action (`/logout` — POST)
- **Entry Point**: Form POST submission containing `csrf_token`.
- **Data Flow**: Request received by Flask, CSRF token verified, session cleared, and user redirected to `/login`.
- **Threat Vector**: Cross-Site Request Forgery (CSRF) and forced cross-site logout via embedded image or link tags.
- **Trust Boundary**: Crossing from client-side state into session termination lifecycle.

### 3. Member Profile Route (`/profile/<int:user_id>` — GET)
- **Entry Point**: Path parameter `user_id` supplied in URL.
- **Data Flow**: Flask router extracts integer identifier, verifies ownership or administrator status, and queries `users` table.
- **Threat Vector**: Insecure Direct Object References (IDOR). A member altering the path parameter to view other members' personal phone numbers, emails, and full names.
- **Trust Boundary**: Crossing between authenticated user session and multi-tenant user profile datastore.

### 4. Administrative Panel (`/admin/users` — GET)
- **Entry Point**: HTTP GET request to `/admin/users`.
- **Data Flow**: Re-verifies user existence and `admin` role against the database on each request, retrieving sanitized user records.
- **Threat Vector**: Broken Function-Level Authorization (BFLA) and privilege escalation via stale or forged session roles.
- **Trust Boundary**: Privilege boundary separating standard `member` role from privileged `admin` role.

### 5. Client Session Cookie (`session` cookie)
- **Entry Point**: HTTP `Cookie` header transmitted on every browser request.
- **Data Flow**: Signed cookie unpacked by Flask's session serializer to extract `user_id`, `role`, and active timestamp.
- **Threat Vector**: Cookie tampering, session fixation, token sniffing over unencrypted connections, inactivity session hijacking, or cross-site script theft.
- **Trust Boundary**: Client-held persistent state transmitted back into server request lifecycle.


## STRIDE Threat Analysis & Mitigation Mapping

The following matrix maps each system asset against the STRIDE threat model categories, identifying potential attack scenarios, affected surfaces, and specific mitigations implemented in `secure/app.py`:

| Asset | STRIDE Category | Threat Scenario | Attack Surface | Mitigation in `secure/app.py` | Status |
|---|---|---|---|---|---|
| **User Credentials** | **S**poofing | Attacker injects `' OR 1=1 --` into username field to bypass authentication and impersonate `admin`. | `/login` (POST) | **Parameterized Prepared Statements**: DB query uses SQL parameter placeholders (`SELECT * FROM users WHERE username = ?`, `(username,)`) and verifies hashes via `werkzeug.security.check_password_hash`. | Mitigated |
| **User Credentials** | **I**nformation Disclosure | Plaintext passwords dumped from database file or exposed in application error logs. | SQLite database / queries | **One-way Password Hashing**: Passwords are never stored in plaintext; salted and hashed with PBKDF2/scrypt before persistence in `init_db()`. | Mitigated |
| **User Credentials** | **I**nformation Disclosure | Attacker probes `/login` with username dictionaries, observing error messages or response timing differences to enumerate registered members. | `/login` | **Anti-Enumeration Timing Equalization**: Responses return identical HTTP 200 statuses and `Invalid credentials` text for all failures. Non-existent usernames trigger dummy password hashing to equalize timing. | Mitigated |
| **Profile PII** | **I**nformation Disclosure | Member accesses another user's private phone number and email by incrementing ID in URL (IDOR). | `/profile/<int:user_id>` | **Ownership & Role Verification**: Route enforces `if session.get("role") != "admin" and session.get("user_id") != user_id: abort(403)`. | Mitigated |
| **Admin Panel & Data** | **E**levation of Privilege | Standard authenticated member directly requests `/admin/users` to view internal member directory. | `/admin/users` | **Server-Side Access Control Decorator**: Route is protected with `@admin_required`, rejecting unauthorized roles with HTTP 403 Forbidden. | Mitigated |
| **Admin Panel & Data** | **E**levation of Privilege | A demoted or deleted user continues accessing administrative endpoints using an existing signed session cookie. | Authenticated routes (`/admin/users`, `/`) | **Request-Level Role Re-Validation**: `@login_required` and `@admin_required` decorators query the database on every request to confirm user existence and active role, clearing sessions on revoked accounts. | Mitigated |
| **Admin Panel & Data** | **I**nformation Disclosure | Admin user listing inadvertently renders password hashes or confidential credentials in the HTML view. | `/admin/users` template | **Projection Whitelisting**: SQL query strictly selects only non-sensitive columns (`SELECT id, username, role, email FROM users`), omitting password hash fields entirely. | Mitigated |
| **Session Tokens** | **T**ampering | Client modifies session cookie payload to elevate role from `member` to `admin`. | HTTP `Cookie` header | **Cryptographic HMAC Signing**: Flask signs session cookies using HMAC with server-side `app.secret_key`, rejecting modified or forged payloads. | Mitigated |
| **Session Tokens** | **T**ampering / **S**poofing | Attacker tricks user's browser into submitting unauthorized requests or logging out via malicious third-party links or images. | `/login`, `/logout` | **CSRFProtect & POST-Only Logout**: Enforced `Flask-WTF` `CSRFProtect` verifying dynamic CSRF tokens; restricted `/logout` strictly to POST requests with tokens. | Mitigated |
| **Session Tokens** | **S**poofing | Session fixation attack where attacker pre-seeds session identifier prior to login. | `/login` | **Session Regeneration on Authentication**: `session.clear()` is executed immediately upon successful credential validation before setting new identity tokens. | Mitigated |
| **Session Tokens** | **S**poofing | Attacker accesses an unattended terminal or reuses an old dormant cookie after days of inactivity. | All authenticated routes | **Session Expiry & Server-Side Idle Timeout**: Configured `PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)` and enforced a 30-minute idle check via `@app.before_request`, invalidating abandoned sessions. | Mitigated |
| **Session Tokens** | **I**nformation Disclosure | Cross-site scripting (XSS) payload executes in client browser and steals session token. | Session cookie | **HttpOnly, SameSite, and Cookie Prefixes**: `SESSION_COOKIE_HTTPONLY = True` prevents JavaScript reading cookies; `SESSION_COOKIE_SAMESITE = 'Lax'`; production environments use RFC 6265bis `__Host-` prefixed secure cookies. | Mitigated |
| **Authentication Service** | **D**enial of Service | Malicious actor repeatedly submits incorrect passwords for targeted users to lock legitimate accounts out of the application. | `/login` | **DoS-Resistant Lockout Architecture**: Lockouts are tracked per `(username, ip_address)` pair with exponential backoff timers, preventing external attackers from locking victims out across different IP addresses. | Mitigated |
| **Login Service** | **D**enial of Service / Brute Force | Automated credential stuffing bot submits thousands of rapid password guesses against `/login`. | `/login` endpoint | **Dual-Layer Throttling**: Integrated `Flask-Limiter` at 5 req/min per IP address returning HTTP 429, coupled with DB-backed lockout after 5 consecutive failures. | Mitigated |
| **Application Integrity** | **R**epudiation | Malicious or rogue user attempts brute-force, access unauthorized endpoints, or logs out with no verifiable audit trail. | `/login`, `/logout`, `/admin/users` | **Structured Security Audit Logging**: Integrated `secure.audit` logging security events (login success, failure, lockout, 403, and logout) with user IDs, timestamps, and IP addresses without logging passwords. | Mitigated |


## Residual Risks & Operational Limitations

While `secure/app.py` establishes a defense-in-depth security posture, the following residual risks remain within the current application scope:

1. **SQLite Concurrency & File Security**:
   SQLite employs database-level file locks. Under high write concurrency (such as distributed brute-force floods recording failed attempts), SQLite can experience database lock contention (`sqlite3.OperationalError: database is locked`). Furthermore, SQLite relies entirely on filesystem permissions rather than database user privilege rings.
2. **In-Memory Rate Limit Storage Across Workers**:
   By default, `RATELIMIT_STORAGE_URI` is configured to `memory://`. When deploying with multi-process WSGI servers (e.g. Gunicorn with multiple workers) or multiple container replicas, in-memory rate limit counters are not shared across processes. A distributed memory store (e.g., Redis or Memcached) must be configured in `secure/config.py` in clustered environments.
3. **Absence of Multi-Factor Authentication (MFA)**:
   Authentication relies solely on single-factor passwords. If a user's password is breached through external credential stuffing or shoulder-surfing, no secondary out-of-band factor (e.g. TOTP or WebAuthn) exists to prevent unauthorized access.
4. **No Self-Service Password Reset Workflow**:
   The portal does not feature an automated, cryptographically secure password recovery or reset mechanism. Users who forget credentials require manual administrative re-seeding or database modification.
