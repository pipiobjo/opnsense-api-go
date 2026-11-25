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
   2026-11-16, 2026-11-18, 2026-11-24). Pushes and pull requests test the
   data state pinned in `tools/ci/catalog-ref` (`catalog-v1-<data_id>`),
   so a new data state cannot turn an unrelated change red. New data
   reaches that pin like a new spec commit (point 6): `spec-update.yml`
   proposes it on a branch, `ci.yml` runs the whole suite against it there
   (every series on a VM with every plugin; a plugin that did not install
   fails the pin, since its resources were not tested), and `main` moves
   only when that passed. `catalog-ref` on `main` therefore names the
   newest data the suite passed on, in the git history rather than in a
   cache that expires; a consumer that embeds the same state (ADR 0003)
   embeds tested data. So a new OPNsense release, hotfix or plugin update
   exercises the client within a day, including the checks of OPNsense
   behaviour the client relies on (`TestRecordedBehaviour`). A failure
   notifies nobody; `watchdog.yml` (the spec repository's `alerts.sh`,
   point 6) opens one self-closing `needs-you` issue after 7 days without
   success. It also watches the spec repository's `pipeline.yml` and
   `watchdog.yml`, and the spec's watchdog watches this repository's
   `spec-update.yml` and `watchdog.yml` (amended 2026-11-18): GitHub
   disables all schedules of an inactive repository at once, and a broken
   watchdog tells nobody. The schedule is daily while the client is
   pre-release and becomes weekly or monthly with the first stable release
   (one cron line). The spec repository does not run the client: it knows
   no consumers.
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
   Amended 2026-11-24: the same branch also carries the data pin
   (`tools/ci/catalog-ref`, point 4); only a spec commit whose
   `promote.yml` run passed is followed (the spec's own rule "only
   promoted commits publish"; its `main` accepts direct pushes); a failed
   pin run is run again once automatically, a second failure deletes the
   branch so the next day proposes the pin afresh, and the job stays red
   until a pin passes; after 7 days the watchdog reports it. The VM logs
   of a failed run are kept 14 days, longer than that. The Dependabot
   upkeep is its own job, so a failed pin does not stop it. Before the
   automation, eight pin updates in three days were made by hand.
   Amended 2026-11-25: the pin branch gets a pull request with auto-merge,
   the same path as Dependabot (point 5), and lands the same day its CI
   passes; a later run merges a passed one whose auto-merge did not fire.
   The fast-forward of `main` by the job token was refused by the ruleset
   "main: tested" although the commit carried a green `ci passed` (rule
   suite: "Required status check is expected"); a bypass for GitHub
   Actions would have let every job token push untested commits, so the
   repository setting "Allow GitHub Actions to create and approve pull
   requests" is on instead (no review is required, so the approval part
   grants nothing). `main` holds the tested tree as a rebased commit.
7. **Unknown versions are graded.** Another hotfix revision of a known
   release, or a known plugin version seen on another core of the series,
   is a note (`Instance().Notes`): usual after an update, nothing to do. A
   release or plugin version the data has never seen is a warning
   (`Instance().Warnings`). `UnknownVersion: Refuse` makes both errors.

What stays with a person: a capability `format` change (a new format gets
its own pointer `catalog-v2`; the format-1 pointer and its fixed releases
stay at the last format-1 state, amended 2026-11-24), and a client
change when OPNsense changes its API conventions. The provider's weekly
acceptance tests run the client against each new OPNsense release and
report such a change there.

## What "main is what was tested" means

The ruleset "main: tested" requires the status check `ci passed` for
every change to `main`, and both automatic paths (Dependabot, the pins)
go through it. The ruleset has a bypass for the repository role admin
(set 2026-11-20), and the maintainers' way of working is a direct push
to `main` after the tests passed locally, unit and, for anything the
integration test touches, on throwaway VMs of every series. So:

- For Dependabot and the pins, `main` is exactly what CI tested.
- For a maintainer's push, `ci.yml` runs on `main` after the push, not
  before. A red run on such a commit means `main` holds untested or
  failing code until the next push fixes it; nothing is published from
  `main` by itself (a release is a tag pushed by a person, and
  `release.yml` runs the whole suite again first).
- Removing the bypass would turn every maintainer change into a pull
  request with a VM run of about an hour; the project decided against it
  while one person maintains it. Revisit this when a second maintainer
  joins or before v1.

## Consequences

- Users update the client when they want a code change, not to keep up
  with OPNsense.
- Someone using the client on its own downloads a `catalog-v1-<data_id>`
  release of the spec repository and verifies it (`sha256sum -c
  SHA256SUMS`, `gh attestation verify`, or `tools/ci/catalog.sh`); the
  README shows how.
- Without newer data, fields and resources added by newer OPNsense
  versions are refused until the data is updated. Nothing breaks.
- This repository has no routine work: the scheduled test runs are
  silent while they pass, and the only issue that can open closes itself.
