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
   decides how often to update it; the planned OpenTofu provider embeds one
   pinned state at build time (ADR 0003, amended 2026-11-24).
2. **Releases follow code changes,** tagged when CI is green. A new
   OPNsense release needs no client release.
3. **No secrets, and no change without a test.** CI runs on pushes and
   pull requests: format, vet, unit tests with the race detector on the
   two supported Go releases, short fuzz runs, and the integration tests
   on the newest release of each supported series in a throwaway VM (the
   spec repository's test VM action). No test may skip unless it is on
   the short allowlist `tools/ci/skip-allowlist.txt` with its reason
   (amended 2026-11-18). The only commits made without a person are
   Dependabot updates and the spec pin (points 5 and 6); `main` moves to
   such a commit only after `ci.yml` passed on exactly that commit (a
   fast-forward, no new merge commit).
4. **The client is re-tested when the spec has new data** (amended
   2026-11-16). `spec-update.yml` hashes the newest data the spec
   repository published; for a hash not tested yet it runs the whole CI
   suite against it, then remembers the hash in the Actions cache (no
   commit); only if every plugin installed on every test VM (amended
   2026-11-18: a run with a missing plugin did not test that plugin's
   data, so the next day tests it again). So a new OPNsense release, hotfix or plugin update exercises
   the client within a day, including the checks of OPNsense behaviour the
   client relies on (`TestRecordedBehaviour`). A failure notifies nobody;
   `watchdog.yml` (the spec repository's `alerts.sh`, point 6) opens one
   self-closing `needs-you` issue after 7 days without success. It also
   watches the spec repository's `pipeline.yml` and `watchdog.yml`, and
   the spec's watchdog watches this repository's `spec-update.yml` and
   `watchdog.yml` (amended 2026-11-18): GitHub disables all schedules of
   an inactive repository at once, and a broken watchdog tells nobody. The
   schedule is daily while the client is pre-release and becomes weekly or
   monthly with the first stable release (one cron line). The spec
   repository does not run the client: it knows no consumers.
5. **Dependency updates** concern only the pinned actions (the module has
   no dependencies outside the standard library): Dependabot, monthly,
   grouped, versions at least 7 days old, merged without a person when
   CI passed (amended 2026-11-18; before, each waited for a person).
   Amended 2026-11-20: `automerge.yml` turns on GitHub's auto-merge for
   each Dependabot pull request (the pattern GitHub documents), and GitHub
   merges it once the ruleset "main: tested" is met: the status check
   `ci passed` green on a branch up to date with `main`. `main` then holds
   the tested tree as a rebased commit, not the tested commit itself. The
   earlier design (fast-forward from a `workflow_run`) was not documented
   for Dependabot runs and never proven. A Dependabot pull request behind
   `main` is asked to rebase by `spec-update.yml`; one still open after 14
   days turns it red, so the watchdog reports it.
6. **One pin on the spec repository, kept current without a person**
   (added 2026-11-18). The test VM action and the watchdog script come
   from opnsense-api-spec at the commit in `tools/ci/spec-ref`
   (`tools/ci/spec-ref.sh`), the only place that names a spec commit.
   Dependabot cannot follow it (the spec has no release tags for its
   tools), so `spec-update.yml` does: when the spec's `main` (moved only
   after the spec's own promotion tests) is ahead of the pin, it commits
   the new pin to a branch `spec-pin/<commit>-<main>`, starts `ci.yml`
   there, and the next `spec-update.yml` run fast-forwards `main` to it
   when that CI passed (amended 2026-11-20: `automerge.yml` never saw
   these runs, because GitHub starts no `workflow_run` for a run that the
   job token started; a pin now lands one day after it was proposed).
   A pin whose CI failed keeps `spec-update.yml` red until the spec moves
   on; after 7 days the watchdog reports it. Before, eight pin updates in
   three days were made by hand.
7. **Unknown versions are graded.** Another hotfix revision of a known
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
- This repository has no routine work: the scheduled test runs are
  silent while they pass, and the only issue that can open closes itself.
