#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
# SPDX-License-Identifier: BSD-2-Clause
# The one pin on opnsense-api-spec: the commit whose test VM action
# (ci.yml) and watchdog script (watchdog.yml) this repository uses. It
# lives in tools/ci/spec-ref (a commit hash, one line) and nowhere else.
#
#   tools/ci/spec-ref.sh get        the pinned commit
#   tools/ci/spec-ref.sh latest     the commit at the spec's main (anonymous)
#   tools/ci/spec-ref.sh set SHA    pin SHA
#
# The spec's main only moves after its promotion tests (ADR 0012 there),
# so following it needs no further check here: spec-update.yml proposes a
# new pin on a branch, ci.yml tests it, automerge.yml moves main to exactly
# the tested commit.
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
    echo "$ref" ;;
  set)
    valid "${2:-}"
    echo "$2" > "$FILE" ;;
  *) echo "usage: $0 get | latest | set SHA" >&2; exit 2 ;;
esac
