#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
# SPDX-License-Identifier: BSD-2-Clause
# Tests of tools/ci/api-reached.sh (run in ci.yml).
set -euo pipefail
here=$(dirname "$0")
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
fail=0
m=github.com/pipiobjo/opnsense-api-go
check() { # name, want exit code, cover -func output
  printf '%s\n' "$3" > "$work/func"
  local got=0
  API_REACHED_FUNC="$work/func" "$here/api-reached.sh" unused > "$work/out" 2>&1 || got=$?
  if [ "$got" != "$2" ]; then
    echo "FAIL $1: exit $got, want $2"; sed 's/^/  | /' "$work/out"; fail=1
  else
    echo "ok   $1"
  fi
}
check "all reached" 0 "$m/opnsense/resource.go:93:	Add	80.0%
$m/opnsense/fields.go:207:	Check	100.0%
total:	(statements)	63.0%"
check "exported method never ran fails" 1 "$m/opnsense/resource.go:93:	Add	80.0%
$m/opnsense/fields.go:207:	Check	0.0%"
check "unexported, Error and subpackage do not count" 0 "$m/opnsense/resource.go:93:	Add	80.0%
$m/opnsense/resource.go:600:	offered	0.0%
$m/opnsense/errors.go:47:	Error	0.0%
$m/opnsense/errors.go:207:	Unwrap	0.0%
$m/opnsense/capability/values.go:340:	Offered	0.0%"
check "no function of the package fails" 1 "$m/opnsense/capability/values.go:340:	Offered	50.0%"
exit "$fail"
