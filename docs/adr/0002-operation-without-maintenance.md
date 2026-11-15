# 0002: Operation without routine maintenance: the client is code only

Status: accepted 2026-11-15

## Context

OPNsense publishes a release roughly every two weeks, hotfix revisions in
between, and plugins update on their own schedule. The spec repository
turns each of these into new capability data without a person.

A first draft of this decision had the client embed that data, update it
daily by a bot and tag a release whenever it changed. That would have made
every user of the client, and every project built on it, follow a release
stream of one or more versions a week, most of them changing nothing they
use. It would also have given this repository a scheduled pipeline, bot
commits, a watchdog and failure issues: routine work for whoever maintains
it.

What makes a simpler design possible: the client does not need current
data to be safe. For a firewall newer than its data it uses the nearest
known data of the same series, refuses fields it does not know, and reads
back every write.

## Decision

1. **The client is code only.** It carries no capability data. The caller
   passes a directory (`CapabilityDir`) or a loaded set (`Capabilities`).
   Whoever ships a product built on the client ships the data with it and
   decides how often to update it; the planned OpenTofu provider embeds it
   and updates it weekly.
2. **Releases follow code changes,** tagged when CI is green. A new
   OPNsense release needs no client release.
3. **No schedule, no bot, no secrets.** CI runs on pushes and pull
   requests: format, vet, unit tests with the race detector, and the
   integration tests on the newest release of each supported series in a
   throwaway VM (the spec repository's test VM action).
4. **Dependency updates** concern only the pinned actions (the module has
   no dependencies outside the standard library): Dependabot, monthly,
   grouped, versions at least 7 days old.
5. **Unknown versions are graded.** Another hotfix revision of a known
   release, or a known plugin version seen on another core of the series,
   is a note (`Instance().Notes`): usual after an update, nothing to do. A
   release or plugin version the data has never seen is a warning
   (`Instance().Warnings`). `UnknownVersion: Refuse` makes both errors.

What stays with a person: a capability `format` change (the spec
repository publishes the old format for an overlap period), and a client
change when OPNsense changes its API conventions. The provider's weekly
acceptance tests run the client against each new OPNsense release and
report such a change there.

## Consequences

- Users update the client when they want a code change, not to keep up
  with OPNsense.
- Someone using the client on its own downloads the `catalog` release of
  the spec repository and verifies it (`sha256sum -c SHA256SUMS`,
  `gh attestation verify`); the README shows how.
- Without newer data, fields and resources added by newer OPNsense
  versions are refused until the data is updated. Nothing breaks.
- This repository has no routine work: no scheduled job, no issue that
  opens itself.
