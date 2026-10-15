# College Club Portal — Trust Issues (Security Lab)

![Security CI](https://github.com/visshalb2007/vuln-portal/actions/workflows/security-ci.yml/badge.svg)

A small Flask app demonstrating 3 real vulnerabilities (`vulnerable/`) and
their fixes (`secure/`), built for the "Trust Issues" cybersecurity task.

⚠️ **Local/educational use only. Never deploy `vulnerable/` anywhere public.**

## Setup
```bash
pip install -r requirements.txt
```

## Run the vulnerable version (port 5000)
```bash
cd vulnerable
python app.py
```
Visit http://127.0.0.1:5000 — logins: `admin/admin123`, `alice/alicepw`, `bob/bobpw`

## Run the secure version (port 5001)
```bash
cd secure
python app.py
```
Same logins (passwords now hashed in DB, but login creds unchanged).

## Testing the exploits
```bash
cd poc
chmod +x exploit_demo.sh verify_fix.sh
./exploit_demo.sh      # run while vulnerable/ app is running on :5000
./verify_fix.sh        # run while secure/ app is running on :5001
```

## What's inside
- `vulnerable/` — intentionally broken app (3 vulns, see docs/vulnerabilities.md)
- `secure/` — same app, fixed with role validation, parameterized queries, rate limiting & lockout
- `docs/threat_model.md` — comprehensive STRIDE threat model, asset analysis & trust boundaries
- `docs/vulnerabilities.md` — root cause + impact + fix per vulnerability
- `docs/security_report.md` — assessment summary, scope, limitations
- `poc/` — curl-based exploit and verification scripts
- `tests/` — automated regression test suite (pytest + Flask test client)
- `.github/workflows/security-ci.yml` — automated regression testing and Bandit SAST scanner

## The 3 vulnerabilities
1. **IDOR** on `/profile/<id>` — any user can view any other user's profile
2. **SQL Injection** on `/login` — `admin' --` bypasses authentication
3. **Broken access control** on `/admin/users` — only gated by hiding the UI link, not server-side role check

See `docs/vulnerabilities.md` for full detail on each.
