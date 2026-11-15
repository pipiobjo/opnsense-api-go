#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
# SPDX-License-Identifier: BSD-2-Clause
# Capability data for the integration tests, into DIR (default catalog/):
#
#   tools/ci/catalog.sh [DIR]
#
# 1. The release "catalog" of opnsense-api-spec, if it is published:
#    downloaded without credentials, checked against SHA256SUMS and its
#    build provenance attestation, unpacked.
# 2. Otherwise built from that repository's published pipeline state with
#    its own command, at the commit SPEC_REF (the same code that builds the
#    catalog release).
#
# Prints the newest verified release of each series as a JSON list of
# {series, release} on the last line (the test matrix).
set -euo pipefail

SPEC=pipiobjo/opnsense-api-spec
SPEC_REF="${SPEC_REF:-9882dbddff1fedb52b58237e4d63c7c42f31cdac}"
OUT="${1:-catalog}"
BASE="https://github.com/$SPEC/releases/download"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
get() { env -u GH_TOKEN -u GITHUB_TOKEN curl -fsSL --retry 3 -o "$2" "$BASE/$1"; }

rm -rf "$OUT"; mkdir -p "$OUT"
if get catalog/SHA256SUMS "$work/SHA256SUMS" 2>/dev/null; then
  get catalog/catalog.json "$work/catalog.json"
  get catalog/capabilities.tar.zst "$work/capabilities.tar.zst"
  (cd "$work" && sha256sum --quiet -c SHA256SUMS)
  gh attestation verify "$work/SHA256SUMS" -R "$SPEC" >/dev/null
  cp "$work/catalog.json" "$OUT/"
  zstd -dc "$work/capabilities.tar.zst" | tar -C "$OUT" -xf -
  echo "catalog: release 'catalog' of $SPEC, checksums and attestation verified" >&2
else
  get state/dist.tar.zst "$work/dist.tar.zst"
  mkdir "$work/dist" && zstd -dc "$work/dist.tar.zst" | tar -C "$work/dist" -xf -
  go run "github.com/$SPEC/cmd/opnsense-api-spec@$SPEC_REF" capabilities -dist "$work/dist" -out "$OUT" >&2
  echo "catalog: built from the pipeline state of $SPEC at ${SPEC_REF:0:12} (release 'catalog' not published)" >&2
fi
jq -c '.releases | group_by(.series)
  | map(map(select(. as $r | any($r.compositions[]; .id == $r.current and .verified != null)))
        | select(length > 0) | max_by(.release | split(".") | map(tonumber? // 0))
        | {series, release})' "$OUT/catalog.json"
