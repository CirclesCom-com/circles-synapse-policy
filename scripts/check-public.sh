#!/usr/bin/env bash
# This repository is public: it is the source the Circles AGPL source offer links to. Refuses
# secrets and internal hostnames in tracked files (Daniel's brief of 18 Nov 2026, 12:33). The only
# host allowed in examples is the generic compose name `api` (http://api:3000/...).
set -euo pipefail
cd "$(dirname "$0")/.."
mapfile -t files < <(git ls-files | grep -v -E '^(LICENSE|scripts/check-public\.sh)$')
fail=0
hit() { # label, extended regex
  local out
  out=$(grep -n -I -E -e "$2" -- "${files[@]}" 2>/dev/null || true)
  if [ -n "$out" ]; then echo "FAIL $1:"; printf '  %s\n' "${out//$'\n'/$'\n'  }"; fail=1; fi
}
hit "a private key" '-----BEGIN [A-Z ]*PRIVATE KEY-----'
hit "a token in a known format" '(mct_|syt_|syr_|sk_live_|sk_test_|rk_live_|hvs\.|ghp_|github_pat_|xox[bap]-|AKIA)[A-Za-z0-9_]{8,}'
hit "a secret-like value" "(secret|password|passwd|api[_-]?key|token)[\"']?[[:space:]]*[:=][[:space:]]*[\"'][A-Za-z0-9+/_.=-]{12,}[\"']"
hit "a staging or internal hostname" '(staging\.circlescom\.com|\.staging\.|\.internal\b|\.local\b|\.lan\b)'
hit "a private IP address" '\b(10\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b'
hit "a Circles server address" '\b78\.46\.[0-9]{1,3}\.[0-9]{1,3}\b'
hit "an internal URL other than the generic http://api:3000 example" 'https?://(localhost|127\.0\.0\.1|openbao|synapse|mas|postgres|redis|billing|sygnal)[:/]'
[ "$fail" = 0 ] && echo "ok   no secrets or internal hostnames in ${#files[@]} tracked files"
exit "$fail"
