#!/bin/sh
# Upgrade smoke test: bring up the PREVIOUS release against a database,
# create realistic state, then start the CANDIDATE binary on that same
# database and require it to migrate, start, and serve. Catches start-up
# code that only works on a fresh tenant and migrations that never run.
#
#   ROSTOR_TEST_DATABASE_URL=postgres://... deploy/test-upgrade.sh <previous-binary> <candidate-binary>
set -eu
PREV="$1"; NEW="$2"
: "${ROSTOR_TEST_DATABASE_URL:?set ROSTOR_TEST_DATABASE_URL}"
DATA="$(mktemp -d)"; trap 'kill $PID 2>/dev/null || true; rm -rf "$DATA"' EXIT
export ROSTOR_DATABASE_URL="$ROSTOR_TEST_DATABASE_URL" ROSTOR_DATA_DIR="$DATA" ROSTOR_STATE_DIR="$DATA" \
       ROSTOR_LISTEN=127.0.0.1:18443 ROSTOR_ADMIN_LISTEN=127.0.0.1:18080 ROSTOR_TLS_HOSTS=127.0.0.1

wait_up() { # binary label
  for i in $(seq 1 40); do
    if curl -fsS http://127.0.0.1:18080/healthz >/dev/null 2>&1; then return 0; fi
    if ! kill -0 "$PID" 2>/dev/null; then echo "FAIL: $1 exited before serving"; cat "$DATA/serve.log"; return 1; fi
    sleep 0.5
  done
  echo "FAIL: $1 did not come up"; cat "$DATA/serve.log"; return 1
}

echo "==> previous: $("$PREV" version)"
"$PREV" bootstrap --tenant upgrade-test > "$DATA/bootstrap.out"
TOKEN="$(awk '/admin token/{print $3}' "$DATA/bootstrap.out")"
"$PREV" serve > "$DATA/serve.log" 2>&1 & PID=$!
wait_up previous
export ROSTOR_URL=http://127.0.0.1:18080 ROSTOR_TOKEN="$TOKEN"
# Realistic state: a person with a password, a group, a grant, an enrollment token.
"$PREV" admin user create --username dan --display "Dan" >/dev/null
"$PREV" admin user password --user dan --password "correct-horse-battery" >/dev/null
"$PREV" admin group create --name members >/dev/null
"$PREV" admin group add --group members --user dan >/dev/null
"$PREV" admin grant create --group members --role user --resource-type workstations --resource-id all >/dev/null
"$PREV" admin device token >/dev/null
kill $PID; wait $PID 2>/dev/null || true

echo "==> candidate: $("$NEW" version)"
"$NEW" serve > "$DATA/serve.log" 2>&1 & PID=$!
wait_up candidate
grep -E "applied migration" "$DATA/serve.log" || echo "(no new migrations)"
# The old state is still usable through the new binary.
"$NEW" admin why --user dan --resource-type workstation --resource-id WS-X | grep -q '"decision"' || { echo "FAIL: why through candidate"; exit 1; }
"$NEW" admin audit verify | grep -q '"intact": true' || { echo "FAIL: audit chain after upgrade"; exit 1; }
# And the candidate survives a restart against its own migrated schema.
kill $PID; wait $PID 2>/dev/null || true
"$NEW" serve > "$DATA/serve.log" 2>&1 & PID=$!
wait_up candidate-restart
echo "OK: upgrade from $("$PREV" version) to $("$NEW" version)"
