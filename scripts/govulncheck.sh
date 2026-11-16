#!/usr/bin/env bash
set -euo pipefail

# Echo advisories with no fixed release at the time of writing. Re-evaluate when
# Echo publishes a patched version and remove entries from this list.
ALLOWLIST="GO-2026-6875 GO-2026-6872"

output="$(mktemp)"
errors="$(mktemp)"
trap 'rm -f "$output" "$errors"' EXIT

set +e
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 -format json ./... >"$output" 2>"$errors"
status=$?
set -e

if [ -s "$errors" ]; then
  cat "$errors" >&2
fi

# govulncheck exits 3 when it finds vulnerabilities.
if [ "$status" -ne 0 ] && [ "$status" -ne 3 ]; then
  echo "govulncheck failed with exit code $status" >&2
  exit "$status"
fi

if [ ! -s "$output" ]; then
  echo "govulncheck produced no JSON output" >&2
  exit 1
fi

allowlist_regex="^($(echo "$ALLOWLIST" | tr ' ' '|'))$"
unexpected="$(jq -r 'select((.finding // {}).osv != null) | .finding.osv' "$output" | sort -u | grep -vE "$allowlist_regex" || true)"

if [ -n "$unexpected" ]; then
  echo "Vulnerabilities outside the allowlist were found:" >&2
  echo "$unexpected" >&2
  exit 1
fi

echo "govulncheck: only allow-listed, unfixed advisories remain."
