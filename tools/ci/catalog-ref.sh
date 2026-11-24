#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
# SPDX-License-Identifier: BSD-2-Clause
# The one pin on the capability data: the immutable release
# catalog-v1-<data_id> of opnsense-api-spec that ci.yml tests with. It
# lives in tools/ci/catalog-ref (one line) and nowhere else. On main it
# names the newest data the whole suite passed on: spec-update.yml moves it
# only through a branch whose ci.yml run passed (ADR 0002 point 6).
#
#   tools/ci/catalog-ref.sh get        the pinned release
#   tools/ci/catalog-ref.sh latest     the release the spec's rolling tag
#                                      (CATALOG_ROLLING, default catalog-v1:
#                                      the newest data in format 1) points to
#   tools/ci/catalog-ref.sh set TAG    pin TAG
#
# latest reads only catalog.json (anonymous, no verification): it names a
# candidate; tools/ci/catalog.sh verifies checksums, attestation and the
# data_id when ci.yml downloads it.
set -euo pipefail
FILE="$(dirname "$0")/catalog-ref"
BASE="https://github.com/pipiobjo/opnsense-api-spec/releases/download"

valid() { [[ "$1" =~ ^catalog-v1-[0-9a-f]{16}$ ]] || { echo "error: not a catalog-v1-<data_id> release: '$1'" >&2; exit 1; }; }

case "${1:-}" in
  get)
    ref=$(tr -d '[:space:]' < "$FILE")
    valid "$ref"
    echo "$ref" ;;
  latest)
    id=$(env -u GH_TOKEN -u GITHUB_TOKEN curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 \
      "$BASE/${CATALOG_ROLLING:-catalog-v1}/catalog.json" | jq -r '.data_id // ""')
    valid "catalog-v1-$id"
    echo "catalog-v1-$id" ;;
  set)
    valid "${2:-}"
    echo "$2" > "$FILE" ;;
  *) echo "usage: $0 get | latest | set TAG" >&2; exit 2 ;;
esac
