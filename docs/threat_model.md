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
