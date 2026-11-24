#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
# SPDX-License-Identifier: BSD-2-Clause
# The one pin on opnsense-api-spec: the commit whose test VM action
# (ci.yml) and watchdog script (watchdog.yml) this repository uses. It
# lives in tools/ci/spec-ref (a commit hash, one line) and nowhere else.
#
#   tools/ci/spec-ref.sh get        the pinned commit
#   tools/ci/spec-ref.sh latest     the spec's main, if its promotion passed
#   tools/ci/spec-ref.sh set SHA    pin SHA
#
# latest follows the same rule as the spec's own pipeline ("only promoted
# commits publish", ADR 0012 there): a commit counts only if promote.yml
# succeeded on it. The spec's ruleset does not stop a direct push to its
# main, and this repository runs the pinned commit's test VM action and
# watchdog script; an unpromoted main keeps the current pin (a warning).
# spec-update.yml proposes a new pin on a branch, ci.yml tests it there,
# and main moves to exactly the tested commit. Needs GH_TOKEN (any token
# that can read public repositories) for the run lookup.
set -euo pipefail
FILE="$(dirname "$0")/spec-ref"
SPEC_URL="${SPEC_URL:-https://github.com/pipiobjo/opnsense-api-spec}"

valid() { [[ "$1" =~ ^[0-9a-f]{40}$ ]] || { echo "error: not a commit hash: '$1'" >&2; exit 1; }; }

case "${1:-}" in
  get)
    ref=$(tr -d '[:space:]' < "$FILE")
    valid "$ref"
    echo "$ref" ;;
  latest)
    ref=$(env -u GH_TOKEN -u GITHUB_TOKEN git ls-remote "$SPEC_URL" refs/heads/main | cut -f1)
    valid "$ref"
    promoted=$(gh run list -R "${SPEC_URL#https://github.com/}" -w promote.yml -c "$ref" -s success -L 1 --json databaseId -q '.[0].databaseId // empty')
    if [ -z "$promoted" ]; then
      cur=$(tr -d '[:space:]' < "$FILE")
      valid "$cur"
      echo "::warning::the spec's main ${ref:0:12} has no successful promote.yml run; keeping the pin ${cur:0:12}" >&2
      ref=$cur
    fi
    echo "$ref" ;;
  set)
    valid "${2:-}"
    echo "$2" > "$FILE" ;;
  *) echo "usage: $0 get | latest | set SHA" >&2; exit 2 ;;
esac
