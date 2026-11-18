#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
# SPDX-License-Identifier: BSD-2-Clause
# Capability data for the integration tests, into DIR (default catalog/):
#
#   tools/ci/catalog.sh [DIR]
#   CATALOG_TAG=catalog-v1-<data_id> tools/ci/catalog.sh [DIR]   # a fixed state
#
# A capability data release of opnsense-api-spec: "catalog" (the newest
# state) or the immutable catalog-v1-<data_id> named in CATALOG_TAG.
# Downloaded without credentials, checked against SHA256SUMS and its build
# provenance attestation (only the spec's publishing pipeline on main
# counts), unpacked; a pinned tag must match the data_id inside. Any
# download or verification error fails: there is no unverified fallback.
#
# Prints the data_id on stderr and, on the last line of stdout, the newest
# verified release of each series as a JSON list of {series, release}
# (the test matrix).
set -euo pipefail

SPEC=pipiobjo/opnsense-api-spec
TAG="${CATALOG_TAG:-catalog}"
OUT="${1:-catalog}"
BASE="https://github.com/$SPEC/releases/download"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
get() { env -u GH_TOKEN -u GITHUB_TOKEN curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 -o "$2" "$BASE/$1"; }

rm -rf "$OUT"; mkdir -p "$OUT"
for f in SHA256SUMS catalog.json capabilities.tar.zst; do
  get "$TAG/$f" "$work/$f" || { echo "error: cannot download $BASE/$TAG/$f" >&2; exit 1; }
done
(cd "$work" && sha256sum --quiet -c SHA256SUMS)
gh attestation verify "$work/SHA256SUMS" -R "$SPEC" \
  --signer-workflow "$SPEC/.github/workflows/pipeline.yml" --source-ref refs/heads/main >/dev/null
id=$(jq -r '.data_id // ""' "$work/catalog.json")
if [[ "$TAG" == catalog-v* ]] && [ "${TAG##*-}" != "$id" ]; then
  echo "error: release $TAG contains data_id '$id'" >&2; exit 1
fi
cp "$work/catalog.json" "$OUT/"
zstd -dc "$work/capabilities.tar.zst" | tar -C "$OUT" -xf -
echo "catalog: release '$TAG' of $SPEC, data_id $id, checksums and attestation verified" >&2
jq -c '.releases | group_by(.series)
  | map(map(select(. as $r | any($r.compositions[]; .id == $r.current and .verified != null)))
        | select(length > 0) | max_by(.release | split(".") | map(tonumber? // 0))
        | {series, release})' "$OUT/catalog.json"
