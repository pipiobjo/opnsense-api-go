#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
# SPDX-License-Identifier: BSD-2-Clause
# Tests of tools/ci/skips.sh (run in ci.yml).
set -euo pipefail
here=$(dirname "$0")
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
fail=0
check() { # name, want exit code, allowlist content, log content
  printf '%s\n' "$3" > "$work/list"
  printf '%s\n' "$4" > "$work/log"
  local got=0
  SKIP_ALLOWLIST="$work/list" "$here/skips.sh" "$work/log" > "$work/out" 2>&1 || got=$?
  if [ "$got" != "$2" ]; then
    echo "FAIL $1: exit $got, want $2"; sed 's/^/  | /' "$work/out"; fail=1
  else
    echo "ok   $1"
  fi
}
log='=== RUN   TestA
--- PASS: TestA (0.00s)
=== RUN   TestB/sub#x.y
    --- SKIP: TestB/sub#x.y (0.01s)
--- SKIP: TestC (0.00s)'
check "no skips" 0 "" '--- PASS: TestA (0.00s)'
check "unlisted skip fails" 1 "TestC reason" "$log"
check "nested unlisted skip fails" 1 "TestB/sub#x.y reason" "$log"
check "every skip listed" 0 "TestB/sub#x.y reason one
TestC   reason two" "$log"
check "entry without a reason fails" 1 "TestB/sub#x.y reason
TestC" "$log"
check "prefix of a name is not a match" 1 "TestB/sub reason
TestC reason" "$log"
check "comment lines ignored" 1 "  # TestC reason" '--- SKIP: TestC (0.00s)'
check "real allowlist is well-formed" 0 "$(cat "$here/skip-allowlist.txt")" ''
exit "$fail"
