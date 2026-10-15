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
