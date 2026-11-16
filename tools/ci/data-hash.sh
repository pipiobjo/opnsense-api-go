#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 opnsense-api-go contributors
# SPDX-License-Identifier: BSD-2-Clause
# Prints a hash of the newest capability data opnsense-api-spec published:
# the release "catalog" (its SHA256SUMS) if it exists, else the pipeline
# state (its index.json). Downloads without credentials. The same data
# gives the same hash; spec-update.yml tests the client once per hash.
set -euo pipefail
BASE="https://github.com/pipiobjo/opnsense-api-spec/releases/download"
get() { env -u GH_TOKEN -u GITHUB_TOKEN curl -fsSL --retry 3 "$BASE/$1"; }
if sums=$(get catalog/SHA256SUMS 2>/dev/null); then
  printf 'catalog-%s\n' "$(sha256sum <<<"$sums" | cut -c1-16)"
else
  printf 'state-%s\n' "$(get state/index.json | sha256sum | cut -c1-16)"
fi
