<div align="center">

# 🛡️ Trust Issues: College Club Portal Security Lab

**A Full-Spectrum Cyber Defense Benchmarking Environment & Dual-State Vulnerability Lab**

[![Security CI](https://github.com/visshalb2007/vuln-portal/actions/workflows/security-ci.yml/badge.svg)](https://github.com/visshalb2007/vuln-portal/actions/workflows/security-ci.yml)
![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![Flask 3.x](https://img.shields.io/badge/flask-3.1-000000.svg)
![Tests: 10 Passed](https://img.shields.io/badge/tests-10%20passed-brightgreen.svg)
![Bandit SAST](https://img.shields.io/badge/bandit-0%20high%20findings-success.svg)
![OWASP Top 10](https://img.shields.io/badge/OWASP-A01%20%7C%20A03%20%7C%20A07-orange.svg)
![License: Educational](https://img.shields.io/badge/license-Educational%20Use%20Only-red.svg)

[Threat Model](docs/threat_model.md) • [Vulnerability Catalog](docs/vulnerabilities.md) • [Security Assessment](docs/security_report.md) • [Regression Tests](tests/test_security.py) • [CI Pipeline](.github/workflows/security-ci.yml)

</div>

---

> ⚠️ **LEGAL & ETHICAL DISCLAIMER**  
> This repository contains deliberately vulnerable software designed strictly for educational demonstrations, security audits, and red/blue team training. **Never expose the `vulnerable/` instance to public networks or production infrastructure.**

---

## 📌 Executive Overview

**Trust Issues** is an advanced hands-on cybersecurity laboratory modeling a real-world web application across two parallel architectural states:

1. **`vulnerable/` (The Attack Target)**: A realistic baseline application suffering from pervasive authorization flaws, unparameterized data persistence, plaintext credential storage, and total absence of rate throttling.
2. **`secure/` (The Hardened Baseline)**: An enterprise-grade, defense-in-depth remediation featuring server-side role validation, parameterized data queries, cryptographic password hashing, strict session isolation, automated account lockouts, IP-level rate limiting, and HTTP security headers.

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

## 👥 Seed Credentials & Role Hierarchy

Both environments are pre-seeded with the following test credentials:

| Username | Password | Role | User ID | Permitted Surfaces (Secure) |
|---|---|:---:|:---:|---|
| `admin` | `admin123` | `admin` | `1` | Full administrative access, `/admin/users`, all member profiles, dashboard |
| `alice` | `alicepw` | `member` | `2` | Dashboard, own profile (`/profile/2`) |
| `bob` | `bobpw` | `member` | `3` | Dashboard, own profile (`/profile/3`) |

---

## 🧪 Automated Testing & Verification

### 1. Pytest Automated Regression Suite
The test suite in [`tests/test_security.py`](tests/test_security.py) executes 10 comprehensive security regression tests using isolated SQLite test database fixtures:

```bash
pytest -v
```

**Test Coverage Summary:**
- ✅ `test_sqli_login_bypass_fails`: Verifies SQL injection payloads (`admin' --`, `' OR '1'='1`) fail to authenticate.
- ✅ `test_idor_non_admin_cannot_view_other_profile`: Verifies member `bob` receives `403 Forbidden` attempting to access `/profile/1` or `/profile/2`.
- ✅ `test_broken_access_control_member_cannot_access_admin_users`: Verifies member `bob` receives `403 Forbidden` on `/admin/users`.
- ✅ `test_legitimate_access_member_can_view_own_profile`: Verifies `bob` successfully accesses `/profile/3`.
- ✅ `test_legitimate_access_admin_can_view_admin_users`: Verifies `admin` accesses `/admin/users` with password hash redaction.
- ✅ `test_legitimate_access_admin_can_view_any_profile`: Verifies `admin` can audit member profiles.
- ✅ `test_unauthenticated_requests_redirect_to_login`: Verifies anonymous requests to protected routes redirect to `/login`.
- ✅ `test_account_lockout_after_five_failed_attempts`: Verifies account locks for 5 minutes after 5 bad attempts.
- ✅ `test_successful_login_resets_failed_attempt_counter`: Verifies valid login clears failure counters.
- ✅ `test_ip_rate_limiting_on_login`: Verifies Flask-Limiter returns `429 Too Many Requests` on rapid bursts.

### 2. Static Application Security Testing (Bandit)
Run AST-based static vulnerability scanning against the hardened codebase:

```bash
bandit -r secure/ -lll
```
*Zero high-severity findings identified.*

### 3. Proof-of-Concept Scripts (curl)
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

Every pull request and push to `main` triggers the automated GitHub Actions workflow defined in [`.github/workflows/security-ci.yml`](.github/workflows/security-ci.yml):

```
┌─────────────────────────────────────────────────────────────┐
│                       GitHub Actions CI                     │
└──────────────────────────────┬──────────────────────────────┘
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
┌───────────────────────────────┐   ┌───────────────────────────────┐
│     Automated Unit & SAST     │   │      Bandit Security Scan     │
│   pytest -v --tb=short        │   │      bandit -r secure/ -lll   │
│   (10/10 Tests Must Pass)     │   │   (0 High Findings Required)  │
└───────────────────────────────┘   └───────────────────────────────┘
```

---

## 📚 Documentation Catalog

| Document | Purpose |
|---|---|
| [**Threat Model (STRIDE)**](docs/threat_model.md) | Exhaustive architectural threat model analyzing assets, actors, trust boundaries, and STRIDE mitigation mappings. |
| [**Vulnerability Catalog**](docs/vulnerabilities.md) | Detailed vulnerability analysis covering root causes, attack vectors, impacts, and code-level fixes. |
| [**Security Assessment Report**](docs/security_report.md) | Executive summary, methodology, verification results, completed hardening items, and residual risks. |

---

## 🔒 Security Hardening Architecture

### Defense-in-Depth Implementation in `secure/app.py`:

1. **Access Control Decorator**:
   ```python
   def admin_required(f):
       @wraps(f)
       def wrapper(*a, **kw):
           if "user_id" not in session:
               return redirect(url_for("login"))
           if session.get("role") != "admin":
               abort(403)
           return f(*a, **kw)
       return wrapper
   ```
2. **Horizontal IDOR Prevention**:
   ```python
   if session.get("role") != "admin" and session.get("user_id") != user_id:
       abort(403)
   ```
3. **Account Lockout & Brute-Force Defense**:
   ```python
   if failed_attempts >= 5:
       lock_until = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
       db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?", ...)
       return render_template("login.html", error="Account locked, try again later.")
   ```
4. **Hardened HTTP Response Headers**:
   ```python
   @app.after_request
   def set_security_headers(resp):
       resp.headers["X-Content-Type-Options"] = "nosniff"
       resp.headers["X-Frame-Options"] = "DENY"
       resp.headers["Content-Security-Policy"] = "default-src 'self'"
       return resp
   ```

---

<div align="center">
<sub>Crafted for the "Trust Issues" Cybersecurity Benchmark Lab • MIT / Educational Use</sub>
</div>
