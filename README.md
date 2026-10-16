<div align="center">

# 🛡️ Trust Issues: College Club Portal Security Lab

**A Full-Spectrum Cyber Defense Benchmarking Environment & Dual-State Vulnerability Lab**

[![Security CI](https://github.com/visshalb2007/vuln-portal/actions/workflows/security-ci.yml/badge.svg)](https://github.com/visshalb2007/vuln-portal/actions/workflows/security-ci.yml)
[![Coverage: >=90%](https://img.shields.io/badge/coverage-%E2%89%A590%25-brightgreen.svg)](https://github.com/visshalb2007/vuln-portal)
![Python 3.10 | 3.11 | 3.12](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)
![Flask 3.x](https://img.shields.io/badge/flask-3.1-000000.svg)
![Bandit SAST](https://img.shields.io/badge/bandit-passing-success.svg)
![OWASP Top 10](https://img.shields.io/badge/OWASP-A01%20%7C%20A03%20%7C%20A07-orange.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[Threat Model](docs/threat_model.md) • [Vulnerability Catalog](docs/vulnerabilities.md) • [Security Assessment](docs/security_report.md) • [Regression Tests](tests/test_security.py) • [CI Pipeline](.github/workflows/security-ci.yml)

</div>

---

> ⚠️ **LEGAL & ETHICAL DISCLAIMER**  
> This repository contains deliberately vulnerable software designed strictly for educational demonstrations, security audits, and red/blue team training. **Never expose the `vulnerable/` instance to public networks or production infrastructure.**

---

## 📌 Executive Overview

**Trust Issues** is an advanced hands-on cybersecurity laboratory modeling a real-world web application across two parallel architectural states:

1. **`vulnerable/` (The Attack Target)**: A realistic baseline application suffering from pervasive authorization flaws, unparameterized data persistence, plaintext credential storage, and total absence of rate throttling.
2. **`secure/` (The Hardened Baseline)**: A hardened, defense-in-depth remediation featuring server-side role validation, parameterized data queries, cryptographic password hashing, strict session isolation, automated account lockouts, IP-level rate limiting, and HTTP security headers.

Accompanied by a formal **STRIDE Threat Model**, an **Automated Pytest Security Regression Suite**, **curl-based exploit PoCs**, and a **GitHub Actions DevSecOps CI Pipeline** running automated SAST (Bandit) scans.

---

## 🏗️ Architecture & Trust Boundaries

```
                             UNTRUSTED CLIENT / ADVERSARY
                                          │
                   ┌──────────────────────┴──────────────────────┐
                   │                                             │
      [Attack Vector: :5000]                        [Defense Vector: :5001]
          vulnerable/                                       secure/
                   │                                             │
 ┌─────────────────▼─────────────────┐       ┌───────────────────▼───────────────────┐
 │ ❌ Concatenated SQL Queries       │       │ 🛡️ Flask-Limiter (5 req/min/IP)       │
 │ ❌ Plaintext Password Storage     │       │ 🛡️ Account Lockout (5 failed attempts)│
 │ ❌ Client-Side Link Hiding        │       │ 🛡️ Parameterized SQLite Queries       │
 │ ❌ No Role Check on /admin/users  │       │ 🛡️ One-Way scrypt/PBKDF2 Password Hash│
 │ ❌ Horizontal IDOR on /profile/:id│       │ 🛡️ Ownership & @admin_required Guards │
 │ ❌ Permissive Cookies & Headers   │       │ 🛡️ CSP, X-Frame-Options, HttpOnly     │
 └─────────────────┬─────────────────┘       └───────────────────┬───────────────────┘
                   │                                             │
                   ▼                                             ▼
          SQLite (club.db)                              SQLite (club.db)
```

---

## 🔬 Vulnerability & Remediation Matrix

| # | Vulnerability | OWASP 2021 | CWE | Vulnerable Vector (`vulnerable/`) | Secure Implementation (`secure/`) | CVSS v3.1 |
|:---:|:---|:---|:---|:---|:---|:---:|
| **1** | **Insecure Direct Object Reference (IDOR)** | A01: Broken Access Control | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | Path parameter in `/profile/<id>` queries database without session ownership verification. | Enforces strict ownership check: `session['user_id'] == id or session['role'] == 'admin'`, returning `403 Forbidden`. | **7.5** (High) |
| **2** | **SQL Injection Authentication Bypass** | A03: Injection | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | Form fields concatenated directly into SQL: `WHERE username='{u}' AND password='{p}'`. Payload `admin' --` bypasses password validation. | Parameterized prepared statement (`?` binding) coupled with irreversible password hashing (`check_password_hash`). | **9.8** (Critical) |
| **3** | **Broken Function-Level Authorization (BFLA)** | A01: Broken Access Control | [CWE-285](https://cwe.mitre.org/data/definitions/285.html) | Administrative panel `/admin/users` only hidden from UI template; direct HTTP GET exposes entire user database. | Server-side `@admin_required` decorator validates session claims and rejects unauthorized requests with `403`. | **8.8** (High) |
| **4** | **Unthrottled Brute-Force & Credential Stuffing** | A07: Identification & Auth Failures | [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | Login endpoint accepts unlimited attempts per IP and per username without rate throttling or lockout. | **Dual Defense**: `Flask-Limiter` enforces 5 req/min per IP, and DB-backed account lockout locks username for 5 minutes after 5 consecutive failures. | **7.5** (High) |

---

## 🚀 Quickstart & Installation

### 1. Prerequisites
- **Python**: `>= 3.10` (Python 3.11 recommended)
- **Git**

### 2. Environment Setup
```bash
# Clone the repository
git clone https://github.com/visshalb2007/vuln-portal.git
cd vuln-portal

# Create and activate virtual environment
python -m venv .venv
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# On macOS / Linux:
source .venv/bin/activate

# Install all runtime, test, and security dependencies
pip install -r requirements.txt
```

### 3. Launching Applications

Run each application in dedicated terminal instances:

```bash
# Terminal 1 — Start Vulnerable Service (Port 5000)
cd vulnerable
python app.py

# Terminal 2 — Start Hardened Service (Port 5001)
cd secure
python app.py
```

| Service | Address | Access Port | Debug Mode |
|---|---|:---:|:---:|
| **Vulnerable Target** | `http://127.0.0.1:5000` | `5000` | Enabled (Dangerous) |
| **Hardened Target** | `http://127.0.0.1:5001` | `5001` | Disabled (Production Baseline) |

---

## ⚙️ Configuration & Environment Variables

The hardened baseline application (`secure/`) is managed through `secure/config.py` and supports the following environment variables:

| Variable | Description | Default | Production Requirement |
|---|---|---|---|
| `SECRET_KEY` | Cryptographic secret for signing session cookies and CSRF tokens. | None | **Mandatory** (app fails fast at startup if missing in non-testing mode). |
| `DATABASE` | File path to the SQLite database. | `secure/club.db` | Optional |
| `RATELIMIT_STORAGE_URI` | Storage backend URI for `Flask-Limiter` throttling. | `memory://` | Optional (e.g. `redis://localhost:6379/0` for distributed workers) |
| `SESSION_COOKIE_SECURE` | Enforces the `Secure` flag on session cookies. | `true` | Optional (`true` in production, `false` for local HTTP testing) |
| `SEED_ADMIN_PASSWORD` | Seed password for the initialized `admin` user account. | Randomly generated | Optional (read from env or generated randomly) |
| `SEED_ALICE_PASSWORD` | Seed password for the initialized `alice` user account. | Randomly generated | Optional (read from env or generated randomly) |
| `SEED_BOB_PASSWORD` | Seed password for the initialized `bob` user account. | Randomly generated | Optional (read from env or generated randomly) |

---

## 🔒 Security Design Decisions

1. **Fail-Fast Configuration**: In production (`TESTING=False`), the application strictly refuses to start without a valid `SECRET_KEY`, avoiding fallback to insecure hardcoded defaults.
2. **Anti-Enumeration Protection**: All credential failures (unknown username, wrong password, or locked account) return identical HTTP 200 responses with the message `Invalid credentials`. Unknown usernames trigger dummy password hashing to neutralize timing side-channels.
3. **DoS-Resistant Account Lockout**: Lockout thresholds (5 failed attempts) and exponential backoff timers are tracked on `(username, ip_address)` composite keys, preventing attackers from executing denial-of-service lockouts against victims from external IPs.
4. **Request-Level Authorization Re-Validation**: The `@login_required` and `@admin_required` decorators query the database on every request to confirm user existence and active role, immediately revoking access if an account is demoted or deleted.
5. **CSRF Protection & POST-Only Logout**: State-changing endpoints are protected via `Flask-WTF` `CSRFProtect`. The `/logout` route accepts only POST requests containing valid CSRF tokens to prevent cross-site logout abuse.
6. **Modern Cookie & Header Hardening**: Session cookies utilize RFC 6265bis `__Host-` prefixes in production, strict 30-minute idle timeouts, `HttpOnly`, `SameSite=Lax`, and complete security headers (`Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, `Cross-Origin-Opener-Policy: same-origin`, tightened `Content-Security-Policy`, and `Cache-Control: no-store` on authenticated views).
7. **Structured Security Audit Logging**: Sensitive events (successful authentications, failed logins, account lockouts, HTTP 403 access rejections, and logouts) are logged with user identifiers and IP addresses without ever logging plain passwords.

---

## 👥 Seed Credentials & Role Hierarchy

Both environments support pre-seeded test credentials (in `TestingConfig` or configurable via environment variables):

| Username | Default Password | Role | User ID | Permitted Surfaces (Secure) |
|---|---|:---:|:---:|---|
| `admin` | `admin123` | `admin` | `1` | Full administrative access, `/admin/users`, all member profiles, dashboard |
| `alice` | `alicepw` | `member` | `2` | Dashboard, own profile (`/profile/2`) |
| `bob` | `bobpw` | `member` | `3` | Dashboard, own profile (`/profile/3`) |

---

## 🧪 Automated Testing & Verification

### 1. Pytest Automated Regression Suite
The test suite in [`tests/test_security.py`](tests/test_security.py) and [`tests/test_vulnerable.py`](tests/test_vulnerable.py) executes 59 automated tests with a `>= 90%` code coverage gate:

```bash
pytest -v --cov=secure --cov-fail-under=90
```

**Key Test Capabilities:**
- SQL injection login bypass rejection across diverse payloads.
- IDOR prevention and ownership verification on `/profile/<id>`.
- Broken access control rejection on `/admin/users`.
- CSRF token validation and missing token rejection (HTTP 400).
- POST-only logout verification and GET `/logout` rejection (HTTP 405).
- Anti-enumeration timing equalization and identical failure statuses.
- DoS-resistant lockout per (username, IP) with exponential backoff.
- Session idle timeouts and RFC 6265bis `__Host-` cookie prefixes.
- Immediate access revocation upon user demotion or deletion.
- Parametrized security headers and `Cache-Control: no-store` on authenticated views.
- Structured audit logging verification via `caplog`.
- Input validation and boundary length checks.
- Exploit verification asserting the 3 vulnerabilities remain functional on `vulnerable/`.

### 2. Static Application Security Testing (Bandit)
Run AST-based static vulnerability scanning against the hardened codebase:

```bash
bandit -r secure/ -ll
```
*Zero medium- or high-severity findings identified.*

### 3. Dependency Vulnerability Auditing (pip-audit)
Scan the environment for known dependency CVEs:

```bash
pip-audit
```
*Zero known dependency vulnerabilities identified.*

### 4. Proof-of-Concept Scripts (curl)
Automated verification scripts are provided in [`poc/`](poc/):

```bash
cd poc
chmod +x exploit_demo.sh verify_fix.sh

# Exploit demonstration against vulnerable instance (:5000)
./exploit_demo.sh

# Fix verification against hardened instance (:5001)
./verify_fix.sh
```

---

## ⚙️ DevSecOps & CI Pipeline

Every pull request and push triggers the automated GitHub Actions workflow defined in [`.github/workflows/security-ci.yml`](.github/workflows/security-ci.yml):

```
┌─────────────────────────────────────────────────────────────┐
│                       GitHub Actions CI                     │
└──────────────────────────────┬──────────────────────────────┘
                               │
             ┌─────────────────┴─────────────────┐
             ▼                                   ▼
┌───────────────────────────────┐   ┌───────────────────────────────┐
│     Multi-Version Matrix      │   │       PoC Verification        │
│   Python 3.10 / 3.11 / 3.12   │   │   Boots :5000 & :5001         │
│   • Ruff Linter               │   │   • Runs exploit_demo.sh      │
│   • Pytest --cov (>= 90%)     │   │   • Runs verify_fix.sh        │
│   • Bandit SAST (-ll)         │   │   (Asserts HTTP status codes) │
│   • pip-audit Vulnerability   │   └───────────────────────────────┘
│   • Uploads Coverage Report   │
└───────────────────────────────┘
```

---

## 📚 Documentation Catalog

| Document | Purpose |
|---|---|
| [**Threat Model (STRIDE)**](docs/threat_model.md) | Exhaustive architectural threat model analyzing assets, actors, trust boundaries, and STRIDE mitigation mappings. |
| [**Vulnerability Catalog**](docs/vulnerabilities.md) | Detailed vulnerability analysis covering root causes, attack vectors, impacts, and code-level fixes. |
| [**Security Assessment Report**](docs/security_report.md) | Executive summary, methodology, verification results, completed hardening items, and residual risks. |

---

<div align="center">
<sub>Released under the <a href="LICENSE">MIT License</a>.</sub>
</div>
