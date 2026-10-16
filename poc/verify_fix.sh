#!/bin/bash
set -euo pipefail

BASE="${BASE_URL:-http://127.0.0.1:5001}"
COOKIE_JAR="$(mktemp -t cookies.XXXXXX)"
trap 'rm -f "$COOKIE_JAR"' EXIT

echo "=== [SECURE APP] Verifying Vulnerability Fixes ==="

get_csrf() {
  curl -s -c "$COOKIE_JAR" "$BASE/login" | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p'
}

# 1. SQL Injection blocked
echo "[1/3] Verifying SQL Injection is blocked..."
CSRF_TOKEN=$(get_csrf)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X POST "$BASE/login" \
  --data-urlencode "csrf_token=$CSRF_TOKEN" \
  --data-urlencode "username=admin' --" \
  --data-urlencode "password=anything")

if [ "$STATUS" -ne 200 ]; then
  echo "[-] Fix verification failed: expected HTTP 200 (re-render login with error), got $STATUS"
  exit 1
fi
echo "[+] PASSED: SQL Injection rejected (HTTP $STATUS)"

# 2. IDOR blocked
echo "[2/3] Verifying IDOR on /profile/1 is blocked (403)..."
# Authenticate legitimately as bob
CSRF_TOKEN=$(get_csrf)
LOGIN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X POST "$BASE/login" \
  --data-urlencode "csrf_token=$CSRF_TOKEN" \
  --data-urlencode "username=bob" \
  --data-urlencode "password=bobpw")

if [ "$LOGIN_STATUS" -ne 302 ]; then
  echo "[-] Setup failed: expected HTTP 302 on valid login, got $LOGIN_STATUS"
  exit 1
fi

IDOR_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" "$BASE/profile/1")
if [ "$IDOR_STATUS" -ne 403 ]; then
  echo "[-] Fix verification failed: expected HTTP 403 Forbidden for IDOR attempt, got $IDOR_STATUS"
  exit 1
fi
echo "[+] PASSED: IDOR attempt blocked with HTTP 403 Forbidden"

# 3. Broken Access Control blocked
echo "[3/3] Verifying Broken Access Control on /admin/users is blocked (403)..."
ADMIN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" "$BASE/admin/users")
if [ "$ADMIN_STATUS" -ne 403 ]; then
  echo "[-] Fix verification failed: expected HTTP 403 Forbidden on /admin/users, got $ADMIN_STATUS"
  exit 1
fi
echo "[+] PASSED: Unauthorized admin access blocked with HTTP 403 Forbidden"

echo "=== All 3 security fixes verified successfully ==="
