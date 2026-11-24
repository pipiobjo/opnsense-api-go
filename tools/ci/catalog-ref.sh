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
#   tools/ci/catalog-ref.sh latest     the newest format-1 data: the release
#                                      the spec's pointer release catalog-v1
#                                      names (a line "data_id: <id>" in its
#                                      notes)
#   tools/ci/catalog-ref.sh set TAG    pin TAG
#
# latest reads no data and verifies nothing: it names a candidate;
# tools/ci/catalog.sh verifies checksums, attestation and the data_id when
# ci.yml downloads it. Until the spec has published the pointer (HTTP 404,
# and only then) the data_id comes from catalog.json of the rolling
# release "catalog"; any other error fails.
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
    api="https://api.github.com/repos/pipiobjo/opnsense-api-spec/releases/tags/catalog-v1"
    auth=()
    [ -z "${GH_TOKEN:-}" ] || auth=(-H "Authorization: Bearer $GH_TOKEN")
    body=$(mktemp); trap 'rm -f "$body"' EXIT
    code=$(curl -sSL --retry 5 --retry-delay 5 -o "$body" -w '%{http_code}' "${auth[@]}" \
      -H "Accept: application/vnd.github+json" "$api")
    case "$code" in
      200) id=$(jq -r '.body // ""' "$body" | sed -n 's/^data_id: *\([0-9a-f]\{16\}\)[[:space:]]*$/\1/p' | head -n 1) ;;
      404) echo "::warning::the spec has no pointer release catalog-v1 yet; using the rolling release catalog" >&2
           id=$(env -u GH_TOKEN -u GITHUB_TOKEN curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 \
             "$BASE/catalog/catalog.json" | jq -r '.data_id // ""') ;;
      *) echo "error: $api answered HTTP $code" >&2; exit 1 ;;
    esac
    valid "catalog-v1-$id"
    echo "catalog-v1-$id" ;;
  set)
    valid "${2:-}"
    echo "$2" > "$FILE" ;;
  *) echo "usage: $0 get | latest | set TAG" >&2; exit 2 ;;
esac
