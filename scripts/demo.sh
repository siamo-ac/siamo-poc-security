#!/usr/bin/env bash
# End-to-end demo of the security POC.
# Usage: ./scripts/demo.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$PATH:$HOME/workspace/toolchains/go/bin"

BASE="https://127.0.0.1:8443"

echo "==> building and starting server..."
go build -o /tmp/siamo-poc-security ./cmd/server
rm -rf /tmp/pocsec-data
/tmp/siamo-poc-security -data /tmp/pocsec-data >/tmp/pocsec.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
sleep 1

echo "==> 1. /public needs no token:"
curl -sk "$BASE/public"; echo

echo "==> 2. /protected with NO token -> expect 401:"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" "$BASE/protected"

echo "==> 3. wrong login -> expect 401:"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" -X POST "$BASE/login" \
  -H 'Content-Type: application/json' -d '{"user":"admin","password":"wrong"}'

echo "==> 4. login with demo creds (admin / demo1234):"
TOKEN=$(curl -sk -X POST "$BASE/login" -H 'Content-Type: application/json' \
  -d '{"user":"admin","password":"demo1234"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
echo "token issued (first 40 chars): ${TOKEN:0:40}..."

echo "==> 5. /protected WITH token -> expect 200:"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" -H "Authorization: Bearer $TOKEN" "$BASE/protected"

echo "==> 6. store a secret, read it back:"
curl -sk -X POST "$BASE/secrets/api-key" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"value":"shhh-very-secret"}'; echo
curl -sk -H "Authorization: Bearer $TOKEN" "$BASE/secrets/api-key"; echo

echo "==> 7. what is actually on disk (data/secrets.json)?"
cat /tmp/pocsec-data/secrets.json; echo
echo "   -> the plaintext 'shhh-very-secret' appears NOWHERE above."

echo "==> 8. OAuth2 client_credentials grant (machine-to-machine, no human):"
OAUTH_TOKEN=$(curl -sk -X POST "$BASE/oauth2/token" \
  -d 'grant_type=client_credentials' \
  -d 'client_id=svc-reporting' \
  -d 'client_secret=svc-secret-42' | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
echo "access token issued (first 40 chars): ${OAUTH_TOKEN:0:40}..."

echo "==> 9. wrong client secret -> expect 401 invalid_client:"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" -X POST "$BASE/oauth2/token" \
  -d 'grant_type=client_credentials' -d 'client_id=svc-reporting' -d 'client_secret=nope'

echo "==> 10. /protected WITH the OAuth2 access token -> expect 200:"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" -H "Authorization: Bearer $OAUTH_TOKEN" "$BASE/protected"
curl -sk -H "Authorization: Bearer $OAUTH_TOKEN" "$BASE/protected"; echo

echo
echo "Demo complete. Also try: curl -kv $BASE/public | grep -i 'SSL connection\|TLS' to see the handshake."
