#!/usr/bin/env sh
# Post a Constellation scan summary as an MR note.
#
# Args:
#   $1  header label (e.g. "scan-image")
#   $2  path to summary text file
#
# Required env (set by GitLab):
#   CI_API_V4_URL, CI_PROJECT_ID, CI_MERGE_REQUEST_IID
# Required from CI/CD variables:
#   CONSTELLATION_GITLAB_TOKEN  Project Access Token with `api` scope
#                                (separate from $CONSTELLATION_TOKEN)
set -eu

label="${1:-constellation}"
path="${2:-/dev/null}"

if [ -z "${CI_MERGE_REQUEST_IID:-}" ]; then
  echo "post-mr-note: not a merge request pipeline; skipping"
  exit 0
fi
if [ -z "${CONSTELLATION_GITLAB_TOKEN:-}" ]; then
  echo "post-mr-note: CONSTELLATION_GITLAB_TOKEN not set; skipping"
  exit 0
fi
if [ ! -f "$path" ]; then
  echo "post-mr-note: $path missing; skipping"
  exit 0
fi

body=$(printf '### Constellation %s\n\n```\n%s\n```\n' \
  "$label" "$(head -c 60000 "$path")")

# jq is part of the constellation/cli image; fall back to escaped sed if not.
payload=$(jq -nc --arg b "$body" '{body: $b}')

curl -sS -X POST \
  --header "PRIVATE-TOKEN: $CONSTELLATION_GITLAB_TOKEN" \
  --header "Content-Type: application/json" \
  --data "$payload" \
  "$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes" \
  > /dev/null

echo "post-mr-note: posted ($label)"
