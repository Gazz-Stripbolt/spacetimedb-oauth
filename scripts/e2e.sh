#!/usr/bin/env bash
# Publish a demo module against the mock provider and run the protocol and browser tests.
#
#   scripts/e2e.sh rust|csharp|typescript
#
# Needs a local server whose modules may call loopback HTTP (scripts/dev-server.sh start),
# because the module talks to the mock provider on 127.0.0.1.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
LANG_=${1:?usage: $0 rust|csharp|typescript}
SERVER=${SERVER:-local}
HTTP=${HTTP:-http://127.0.0.1:3000}
MOCK_PORT=${MOCK_PORT:-4110}
MOCK=http://127.0.0.1:$MOCK_PORT
DB=oauth-$LANG_
FLAVOR=flat
[[ $LANG_ == typescript ]] && FLAVOR=ns

cd "$ROOT"
npm run build -w typescript -w client --silent >/dev/null   # the demos import the packages' compiled dist/
[[ -f demo/web/dist/index.html && -f demo/typescript/src/page.gen.ts ]] || node demo/web/build.mjs

node tests/mock-provider.mjs --port "$MOCK_PORT" > /dev/null &
MOCK_PID=$!
trap 'kill $MOCK_PID 2>/dev/null || true' EXIT
for _ in $(seq 50); do curl -sf -o /dev/null "$MOCK/admin/stats" && break; sleep 0.1; done

export OAUTH_SECRET=${OAUTH_SECRET:-e2e-$(date +%s%N)-not-a-real-secret}
export OAUTH_CONFIG=$(cat <<JSON
{
  "base_url": "$HTTP/v1/database/$DB",
  "state_ttl_secs": 8,
  "providers": {
    "mock": {
      "preset": "generic",
      "client_id": "demo-client",
      "client_secret": "demo-secret",
      "authorize_url": "$MOCK/authorize",
      "token_url": "$MOCK/token",
      "revoke_url": "$MOCK/revoke",
      "userinfo_url": "$MOCK/userinfo",
      "scopes": "profile api"
    }
  }
}
JSON
)
echo "== publish demo/$LANG_ as $DB"
spacetime publish -s "$SERVER" -y "$DB" -p "demo/$LANG_" --delete-data >/dev/null
echo "== protocol tests ($FLAVOR schema)"
DB=$DB FLAVOR=$FLAVOR HOST=${HTTP/http/ws} MOCK=$MOCK npx tsx tests/server.test.mts 2>&1 | grep -v 'INFO Connecting'
if [[ -f tests/browser.test.mts ]]; then
  echo "== browser tests"
  PAGE="$HTTP/v1/database/$DB/route/" MOCK=$MOCK npx tsx tests/browser.test.mts 2>&1 | grep -v 'INFO Connecting'
fi
