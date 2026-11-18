#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
# SPDX-License-Identifier: BSD-2-Clause
# Refresh the unit tests' capability data from real data of
# opnsense-api-spec, trimmed to what the tests use:
#
#   tools/testdata.sh SRC      SRC: an unpacked catalog (catalog.json and
#                              capabilities/), e.g. from tools/ci/catalog.sh
#
# Keeps the whole catalog (all releases and cores, for the resolver
# tests), the core document without resources (detection), and os-frr
# with its OSPF resources (the fake firewall's resources), the JSON
# Schema of the format, and the version-order table (version-order.json,
# the same file the spec's version comparison is tested against; from SRC
# if the catalog has it, else from the spec at the commit in
# tools/ci/spec-ref). Tests refer to
# fragments by package and version (fragmentOf), never by hash, so a
# refresh after a generator change needs no test change.
set -euo pipefail
SRC="${1:?usage: tools/testdata.sh SRC}"
OUT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/opnsense/capability/testdata/catalog"
rm -rf "$OUT"; mkdir -p "$OUT/capabilities"
jq '.packages |= {opnsense: .opnsense, "os-frr": .["os-frr"]}' "$SRC/catalog.json" > "$OUT/catalog.json"
jq 'del(.actions) | .resources = {}' "$SRC/capabilities/opnsense.json" > "$OUT/capabilities/opnsense.json"
jq 'del(.actions) | .resources |= with_entries(select(.key | startswith("quagga/ospfsettings")))' \
  "$SRC/capabilities/os-frr.json" > "$OUT/capabilities/os-frr.json"
# the format's JSON Schema: schema_test.go checks the model against it
cp "$SRC/capability.schema.json" "$OUT/"
# the version-order table: capability_test.go TestCompareVersions
if [ -f "$SRC/version-order.json" ]; then
  cp "$SRC/version-order.json" "$OUT/"
else
  ref=$("$(dirname "${BASH_SOURCE[0]}")/ci/spec-ref.sh" get)
  env -u GH_TOKEN -u GITHUB_TOKEN curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 -o "$OUT/version-order.json" \
    "https://raw.githubusercontent.com/pipiobjo/opnsense-api-spec/$ref/internal/capability/version-order.json"
fi
jq -e '(.ordered | length > 0) and (.equal | length > 0)' "$OUT/version-order.json" >/dev/null
echo "test data refreshed from $SRC: $(jq -r .generator "$OUT/catalog.json")"
