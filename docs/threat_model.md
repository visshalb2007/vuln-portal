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
- **Capabilities**: Can submit arbitrary HTTP requests, query public endpoints (`/login`, `/logout`), inspect returned HTTP headers, cookies, and attempt brute-force or injection payloads against authentication interfaces.
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
| /profile/<int:user_id>   | GET        | Authenticated     | IDOR, PII leakage         |
| /admin/users             | GET        | Member or Admin   | Broken access control      |
| Session Cookie           | Client-side| All sessions      | Tampering, XSS hijacking  |
+---------------------------------------------------------------------------------------+
```

### 1. Login Form (`/login` — POST)
- **Entry Point**: Form inputs (`username`, `password`).
- **Data Flow**: Untrusted string input received by Flask, processed in database query for user authentication.
- **Threat Vector**: SQL injection via unescaped string formatting (e.g., `' OR '1'='1`), automated credential stuffing, and unthrottled dictionary attacks.
- **Trust Boundary**: Crossing from untrusted public web client into application server and SQLite database.

### 2. Member Profile Route (`/profile/<int:user_id>` — GET)
- **Entry Point**: Path parameter `user_id` supplied in URL.
- **Data Flow**: Flask router extracts integer identifier and queries `users` table to render personal profile template.
- **Threat Vector**: Insecure Direct Object References (IDOR). A member altering the path parameter (e.g., from `/profile/3` to `/profile/1` or `/profile/2`) to view other members' or administrators' phone numbers, emails, and full names without authorization.
- **Trust Boundary**: Crossing between authenticated user session and multi-tenant user profile datastore.

### 3. Administrative Panel (`/admin/users` — GET)
- **Entry Point**: HTTP GET request to `/admin/users`.
- **Data Flow**: Retrieves all user records from database and renders user list template.
- **Threat Vector**: Broken Function-Level Authorization (BFLA) / Forced Browsing. In vulnerable configurations, omitting server-side role verification allows any authenticated non-admin member to view the user list.
- **Trust Boundary**: Privilege boundary separating standard `member` role from privileged `admin` role.

### 4. Client Session Cookie (`session` cookie)
- **Entry Point**: HTTP `Cookie` header transmitted on every browser request.
- **Data Flow**: Signed cookie unpacked by Flask's `securecookie` serializer to extract `user_id` and `role`.
- **Threat Vector**: Cookie tampering, session fixation, token sniffing over unencrypted connections, or cross-site script theft if `HttpOnly` or `SameSite` flags are omitted.
- **Trust Boundary**: Client-held persistent state transmitted back into server request lifecycle.


## STRIDE Threat Analysis & Mitigation Mapping

The following matrix maps each system asset against the STRIDE threat model categories, identifying potential attack scenarios, affected surfaces, and specific mitigations implemented in `secure/app.py`:

| Asset | STRIDE Category | Threat Scenario | Attack Surface | Mitigation in `secure/app.py` | Status |
|-------|-----------------|-----------------|----------------|-------------------------------|--------|
| **User Credentials** | **S**poofing | Attacker injects `' OR 1=1 --` into username field to bypass authentication and impersonate `admin`. | `/login` form (POST) | **Parameterized Queries & Hashing**: DB query uses SQL parameter placeholders (`SELECT * FROM users WHERE username = ?`, `(username,)`) and verifies hashes via `werkzeug.security.check_password_hash`. | Mitigated |
| **User Credentials** | **I**nformation Disclosure | Plaintext passwords dumped from database file or exposed in application error logs. | SQLite database / queries | **One-way Password Hashing**: Passwords are never stored in plaintext; salted and hashed with PBKDF2/scrypt before persistence in `init_db()`. | Mitigated |
| **Profile PII** | **I**nformation Disclosure | Member accesses another user's private phone number and email by incrementing ID in URL (IDOR). | `/profile/<int:user_id>` | **Ownership & Role Verification**: Route enforces `if session.get("role") != "admin" and session.get("user_id") != user_id: abort(403)`. | Mitigated |
| **Admin Panel & Data** | **E**levation of Privilege | Standard authenticated member directly requests `/admin/users` to view internal member directory. | `/admin/users` | **Server-side Access Control Decorator**: Route is protected with `@admin_required`, rejecting unauthorized roles with HTTP 403 Forbidden. | Mitigated |
| **Admin Panel & Data** | **I**nformation Disclosure | Admin user listing inadvertently renders password hashes or confidential credentials in the HTML view. | `/admin/users` template | **Projection Whitelisting**: SQL query strictly selects only non-sensitive columns (`SELECT id, username, role, email FROM users`), omitting password hash fields entirely. | Mitigated |
| **Session Tokens** | **T**ampering | Client modifies session cookie payload to elevate role from `member` to `admin`. | HTTP `Cookie` header | **Cryptographic Signing**: Flask signs session cookies using HMAC with server-side `app.secret_key`, rejecting modified or forged payloads. | Mitigated |
| **Session Tokens** | **I**nformation Disclosure | Cross-site scripting (XSS) payload executes in client browser and steals session token. | Session cookie | **HttpOnly & SameSite Flags**: `SESSION_COOKIE_HTTPONLY = True` prevents JavaScript reading cookies; `SESSION_COOKIE_SAMESITE = 'Lax'` prevents cross-site leakage; CSP headers applied. | Mitigated |
| **Session Tokens** | **S**poofing | Session fixation attack where attacker pre-seeds session identifier prior to login. | `/login` | **Session Invalidation on Auth**: `session.clear()` is called immediately upon successful credential validation before setting new identity tokens. | Mitigated |
| **Login Service** | **D**enial of Service / Brute Force | Automated credential stuffing bot submits thousands of rapid password guesses against `/login`. | `/login` endpoint | **Rate Limiting & Account Lockout**: Integrated `Flask-Limiter` per IP and 5-minute account lockout counter after 5 consecutive failed attempts. | Mitigated (Stage 3) |
| **Application Integrity** | **R**epudiation | Malicious user conducts administrative actions with no trace or audit log. | Administrative actions | **Operational Recommendation**: Implement structured access and failure audit logging. | Planned |


## Residual Risk & Defense-in-Depth Recommendations

While `secure/app.py` directly addresses primary vulnerabilities, the following operational requirements must be maintained in production:

1. **Secret Key Management**: `SECRET_KEY` currently falls back to a development string; production deployments must inject high-entropy secrets via protected environment variables.
2. **TLS / HTTPS Enforcement**: `SESSION_COOKIE_SECURE = True` must be enabled when terminated under TLS to prevent passive network eavesdropping.
3. **Cross-Site Request Forgery (CSRF)**: State-changing POST endpoints (such as future event creation or profile modifications) should incorporate CSRF protection (e.g., Flask-WTF / CSRFProtect).
4. **Automated Verification**: Regular execution of unit/regression security tests and automated static application security testing (SAST) in CI pipelines.
