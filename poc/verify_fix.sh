#!/bin/bash
# PoC verification against the SECURE app (must be running on :5001)
# Shows the same attacks now failing.
BASE="http://127.0.0.1:5001"

echo "=== VULN 2 check: SQLi login bypass should FAIL ==="
curl -s -c cookies.txt -X POST "$BASE/login" \
  --data-urlencode "username=admin' --" \
  --data-urlencode "password=anything" -o /dev/null -w "Status: %{http_code} (expect redirect back to login, no session)\n"

echo ""
echo "=== VULN 1 check: IDOR should be blocked (403) ==="
curl -s -c cookies_bob.txt -X POST "$BASE/login" \
  --data-urlencode "username=bob" --data-urlencode "password=bobpw" -o /dev/null
curl -s -o /dev/null -w "GET /profile/1 as bob -> Status: %{http_code} (expect 403)\n" -b cookies_bob.txt "$BASE/profile/1"

echo ""
echo "=== VULN 3 check: admin route should be blocked (403) ==="
curl -s -o /dev/null -w "GET /admin/users as bob -> Status: %{http_code} (expect 403)\n" -b cookies_bob.txt "$BASE/admin/users"

rm -f cookies.txt cookies_bob.txt
