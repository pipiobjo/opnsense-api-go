#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
# SPDX-License-Identifier: BSD-2-Clause
# The integration tests on several throwaway VMs at once (local runs only;
# docs/testing.md, "Parallel local runs"). The VMs, the split of the
# plugins into groups and the conflict check are the spec repository's
# runner (opnsense-api-spec tools/parallel.sh, in a checkout next to this
# one or in OPNSENSE_SPEC_DIR); this script gives it the test and the merge:
#
#   tools/parallel.sh [--first-slot N] [--auto N] [--out DIR]
#
# Releases: the newest verified release of each series in the pinned
# capability data (tools/ci/catalog.sh, as ci.yml). Groups:
# test/integration/groups.json. Per VM: go test -tags integration scoped to
# the group's packages (OPNSENSE_PACKAGES; the core on one VM), with
# coverage; per series: TestMergedGroups (counts added, floor of the
# series), the skip check over all VMs' logs, the integration coverage
# floor and the exported-API check (tools/ci/api-reached.sh) on the merged
# profile.
#
#   tools/parallel.sh group    (called by the runner on each VM)
#   tools/parallel.sh merge    (called by the runner per release)
set -euo pipefail
export LC_ALL=C
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_DIR="${OPNSENSE_SPEC_DIR:-$HERE/../opnsense-api-spec}"
MODULE=github.com/pipiobjo/opnsense-api-go

case "${1:-}" in
  group)
    # environment from the runner: CORE, PLUGINS, GROUP_DIR, TESTVM_URL, TESTVM_KEYFILE, TESTVM_SLOW
    cd "$HERE"
    pk="$PLUGINS"
    [ "$CORE" = 1 ] && pk="opnsense${pk:+,$pk}"
    rc=0
    OPNSENSE_URL="$TESTVM_URL" OPNSENSE_KEYFILE="$TESTVM_KEYFILE" OPNSENSE_CAPABILITIES="$CATALOG" \
      OPNSENSE_PACKAGES="$pk" OPNSENSE_SUMMARY="$GROUP_DIR/summary.json" TESTVM_SLOW="$TESTVM_SLOW" \
      go test -count=1 -tags integration -timeout 150m -v -coverpkg="$MODULE/..." \
      -coverprofile="$GROUP_DIR/integration.out" ./test/integration/ > "$GROUP_DIR/integration.log" 2>&1 || rc=$?
    grep -E '^(--- FAIL|ok|FAIL)|tested [0-9]+ resources|scoped to' "$GROUP_DIR/integration.log" || true
    exit "$rc" ;;
  merge)
    # environment from the runner: RELEASE, RELEASE_DIR, GROUP_DIRS
    cd "$HERE"
    rc=0 sums=() logs=() profs=()
    for d in $GROUP_DIRS; do sums+=("$d/summary.json"); logs+=("$d/integration.log"); profs+=("$d/integration.out"); done
    OPNSENSE_MERGE="$(IFS=,; echo "${sums[*]}")" go test -count=1 -tags integration -v ./test/integration/ \
      > "$RELEASE_DIR/merge.log" 2>&1 || rc=1
    grep -E '^(--- FAIL|ok|FAIL)|series [0-9.]+, [0-9]+ VMs|tested-floor' "$RELEASE_DIR/merge.log" || true
    tools/ci/skips.sh "${logs[@]}" || rc=1
    # one profile: the first file's mode line, then every block (a block
    # counts as covered when any VM covered it, tools/ci/coverage.sh)
    awk 'FNR == 1 && NR != 1 { next } { print }' "${profs[@]}" > "$RELEASE_DIR/integration.out"
    tools/ci/coverage.sh integration "$RELEASE_DIR/integration.out" "$RELEASE_DIR/coverage" || rc=1
    tools/ci/api-reached.sh "$RELEASE_DIR/integration.out" || rc=1
    exit "$rc" ;;
esac

ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --first-slot|--auto|--out) ARGS+=("$1" "${2:?$1 needs a value}"); shift ;;
    *) sed -n '4,22p' "$0"; exit 2 ;;
  esac
  shift
done
[ -x "$SPEC_DIR/tools/parallel.sh" ] || { echo "error: no opnsense-api-spec checkout with tools/parallel.sh at $SPEC_DIR (set OPNSENSE_SPEC_DIR)" >&2; exit 1; }
cd "$HERE"
mkdir -p .cache
export CATALOG="$HERE/.cache/catalog"
matrix=$(tools/ci/catalog.sh "$CATALOG" | tail -n 1)
exec "$SPEC_DIR/tools/parallel.sh" --matrix "$matrix" --groups "$HERE/test/integration/groups.json" \
  --state "$HERE/.cache/parallel" --first-slot 50 --out "$HERE/.cache/parallel/$(date +%Y%m%d-%H%M%S)" "${ARGS[@]}" \
  --test "'$HERE/tools/parallel.sh' group" --merge "'$HERE/tools/parallel.sh' merge"
