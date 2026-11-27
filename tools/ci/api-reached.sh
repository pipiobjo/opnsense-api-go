#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
# SPDX-License-Identifier: BSD-2-Clause
# Every exported function and method of package opnsense must have run
# against a real firewall at least once:
#
#   tools/ci/api-reached.sh PROFILE
#
# PROFILE is the coverage profile of the integration test (one VM, or the
# merged profile of a parallel run). A method a consumer calls on a
# firewall that only ever met the fake firewall of the unit tests is the
# gap this closes (decision of 2026-11-27, docs/testing.md); a percentage
# floor cannot see it. Not counted: Error, Unwrap, Is and String (they
# format errors and values a healthy firewall does not produce; the unit
# tests check them), and subpackages (opnsense/capability is the data
# format behind FieldInfo). Deterministic, so enforced in every run.
#
# API_REACHED_FUNC=FILE reads `go tool cover -func` output from FILE
# instead (tools/ci/api-reached_test.sh).
set -euo pipefail
export LC_ALL=C
PROFILE="${1:?usage: api-reached.sh PROFILE}"
if [ -n "${API_REACHED_FUNC:-}" ]; then
  funcs=$(cat "$API_REACHED_FUNC")
else
  funcs=$(go tool cover -func="$PROFILE")
fi
# lines: <module>/opnsense/<file>.go:<line>:<tab><name><tab><percent>
missed=$(awk '
  $1 ~ /\/opnsense\/[^\/]+\.go:[0-9]+:$/ && $2 ~ /^[A-Z]/ && $2 !~ /^(Error|Unwrap|Is|String)$/ {
    n++; if ($3 == "0.0%") print $1 " " $2
  }
  END { if (n == 0) print "NONE" }' <<<"$funcs")
if [ "$missed" = NONE ]; then
  echo "::error::api-reached: no exported function of package opnsense in $PROFILE"
  exit 1
fi
if [ -n "$missed" ]; then
  while IFS= read -r m; do
    echo "::error::never ran against the firewall: ${m##*/opnsense-api-go/}"
  done <<<"$missed"
  echo "add a call with a check to test/integration (docs/testing.md, \"Every exported method on a real firewall\")"
  exit 1
fi
echo "api-reached: every exported function of package opnsense ran against the firewall"
