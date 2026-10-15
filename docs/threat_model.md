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
