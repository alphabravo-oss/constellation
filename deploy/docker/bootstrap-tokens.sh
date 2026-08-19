#!/usr/bin/env bash
# bootstrap-tokens.sh — one-shot init job that ensures the compose stack has a usable
# scanner_tokens + runtime_agent_tokens row in Postgres, and writes the raw tokens to a
# shared volume so api / scanner-driver / runtime-agent can pick them up at startup.
#
# Why this exists:
#   The token tables (migrations 008 + 029) store a sha256 HASH of the raw token, not the
#   raw value. There is no SQL path to get back to the raw value once issued. So either:
#     (a) the compose stack mints tokens at boot and stashes them in a shared volume, OR
#     (b) every service ships with a baked-in dev token and the migrations seed matching
#         rows — which is the path we explicitly want to avoid (committed dev secrets).
#   This script is option (a).
#
# Idempotency:
#   On every boot the script checks the /run/constellation-tokens/ directory. If both
#   scanner.token and runtime-agent.token already exist AND their sha256 hashes match
#   rows in the DB, we exit clean. Otherwise we rotate.

set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${TOKEN_DIR:=/run/constellation-tokens}"
: "${ORG_NAME:=demo}"

mkdir -p "${TOKEN_DIR}"
chmod 0755 "${TOKEN_DIR}"

# Wait for the orgs table to be ready. Migrations service is a separate depends_on but
# this loop adds belt-and-suspenders for cold starts.
for attempt in {1..30}; do
  if psql "${DATABASE_URL}" -tAc "SELECT 1 FROM information_schema.tables WHERE table_name = 'orgs'" \
       | grep -q '^1$'; then
    break
  fi
  echo "bootstrap-tokens: waiting for migrations (attempt ${attempt})"
  sleep 2
done

# Ensure the demo org exists so we have an org_id to attach tokens to. The seed service
# also creates this row; either order is fine (ON CONFLICT keeps it idempotent).
ORG_ID="$(psql "${DATABASE_URL}" -tAqc "
  INSERT INTO orgs (name, display_name, region, ai_enabled)
  VALUES ('${ORG_NAME}', '${ORG_NAME} (compose bootstrap)', 'local', FALSE)
  ON CONFLICT (name) DO UPDATE SET display_name = orgs.display_name
  RETURNING id::text;
" | head -n1 | tr -d '[:space:]')"

if [[ -z "${ORG_ID}" ]]; then
  echo "bootstrap-tokens: failed to resolve org_id for '${ORG_NAME}'" >&2
  exit 1
fi
echo "bootstrap-tokens: org=${ORG_NAME} id=${ORG_ID}"

# generate_token <prefix>
#   Emits a <prefix>_<base64url> string on stdout. 32 random bytes -> base64url -> tag.
generate_token() {
  local prefix="$1"
  local raw
  raw="$(openssl rand 32 | base64 | tr -d '=\n' | tr '/+' '_-')"
  printf '%s_%s' "${prefix}" "${raw}"
}

# upsert_token <table> <name> <raw>
#   Hashes <raw>, deletes any prior row for this (org, name), inserts fresh.
upsert_token() {
  local table="$1" name="$2" raw="$3" hash
  hash="$(printf '%s' "${raw}" | openssl dgst -sha256 -hex | awk '{print $NF}')"
  psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -q -c "
    DELETE FROM ${table} WHERE org_id = '${ORG_ID}' AND name = '${name}';
    INSERT INTO ${table} (org_id, name, token_hash, expires_at)
    VALUES ('${ORG_ID}', '${name}', '${hash}', NOW() + INTERVAL '365 days');
  " >/dev/null
}

# token_matches <table> <name> <raw>  -> 0 if a row exists with this hash, else 1
token_matches() {
  local table="$1" name="$2" raw="$3" hash got
  hash="$(printf '%s' "${raw}" | openssl dgst -sha256 -hex | awk '{print $NF}')"
  got="$(psql "${DATABASE_URL}" -tAc "
    SELECT 1 FROM ${table}
     WHERE org_id = '${ORG_ID}' AND name = '${name}' AND token_hash = '${hash}'
       AND revoked_at IS NULL LIMIT 1;
  " | tr -d '[:space:]')"
  [[ "${got}" == "1" ]]
}

write_token_file() {
  local path="$1" raw="$2"
  printf '%s' "${raw}" > "${path}.tmp"
  chmod 0644 "${path}.tmp"
  mv -f "${path}.tmp" "${path}"
}

# Scanner token.
SCAN_TOKEN_FILE="${TOKEN_DIR}/scanner.token"
SCAN_NAME="compose-scanner-driver"
if [[ -s "${SCAN_TOKEN_FILE}" ]] \
   && token_matches scanner_tokens "${SCAN_NAME}" "$(cat "${SCAN_TOKEN_FILE}")"; then
  echo "bootstrap-tokens: scanner_tokens row already current"
else
  raw="$(generate_token cst)"
  upsert_token scanner_tokens "${SCAN_NAME}" "${raw}"
  write_token_file "${SCAN_TOKEN_FILE}" "${raw}"
  echo "bootstrap-tokens: rotated scanner_tokens row (file=${SCAN_TOKEN_FILE})"
fi

# Runtime-agent token.
RA_TOKEN_FILE="${TOKEN_DIR}/runtime-agent.token"
RA_NAME="compose-runtime-agent"
if [[ -s "${RA_TOKEN_FILE}" ]] \
   && token_matches runtime_agent_tokens "${RA_NAME}" "$(cat "${RA_TOKEN_FILE}")"; then
  echo "bootstrap-tokens: runtime_agent_tokens row already current"
else
  raw="$(generate_token cra)"
  upsert_token runtime_agent_tokens "${RA_NAME}" "${raw}"
  write_token_file "${RA_TOKEN_FILE}" "${raw}"
  echo "bootstrap-tokens: rotated runtime_agent_tokens row (file=${RA_TOKEN_FILE})"
fi

# Pin the org_id for the discoverer and any other downstream service that needs it.
write_token_file "${TOKEN_DIR}/org.id" "${ORG_ID}"
echo "bootstrap-tokens: wrote org.id"

echo "bootstrap-tokens: done"
