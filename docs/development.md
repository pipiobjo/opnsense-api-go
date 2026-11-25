# Development and operation

How to work on the client, and how to run a copy of this repository with
its automation. Commands for tests: [CONTRIBUTING.md](../CONTRIBUTING.md).
Why the automation looks as it does:
[ADR 0002](adr/0002-operation-without-maintenance.md).

## Workflows

| Workflow | When | What |
|---|---|---|
| `ci.yml` | push to `main`, pull request, started by `spec-update.yml`, called by `release.yml` | unit tests (two Go releases, race detector, fuzz seeds, mutant table, coverage, SBOM, govulncheck); the data pinned in `tools/ci/catalog-ref`; integration tests on a throwaway VM per series; the required check `ci passed` |
| `spec-update.yml` | daily | moves `tools/ci/spec-ref` and `tools/ci/catalog-ref` through a tested branch `spec-pin/...`; asks Dependabot pull requests behind `main` to rebase |
| `automerge.yml` | Dependabot pull request | turns on GitHub's auto-merge (rebase) |
| `watchdog.yml` | daily | the one `needs-you` issue (the spec repository's `tools/ci/alerts.sh`) |
| `release.yml` | a tag `v*` pushed by a maintainer | the whole `ci.yml`, then a GitHub release with SBOM, coverage, `SHA256SUMS` and attestations |

No workflow needs a secret; all use the job token.

## Running your own copy

The client depends on opnsense-api-spec for three things: the capability
data (`tools/ci/catalog.sh`, the release in `tools/ci/catalog-ref`), the
test VM action (`ci.yml`), and the watchdog script (`watchdog.yml`), both
at the commit in `tools/ci/spec-ref`. A copy keeps using the upstream
spec repository; to use your own copy of the spec as well, change the
repository name in `tools/ci/catalog.sh`, `tools/ci/catalog-ref.sh`,
`tools/ci/spec-ref.sh` (`SPEC_URL`) and the spec checkout in `ci.yml`
and `watchdog.yml`.

1. Fork or copy the repository.
2. Settings -> General: allow auto-merge; allow rebase merging;
   automatically delete head branches.
3. Settings -> Actions -> General: workflow permissions read-only;
   allowed actions "selected" with full commit hashes required; approval
   for workflows from fork pull requests. The workflows ask for the write
   permissions they need per job.
4. Rulesets, as in this repository:
   - "main: no force push, no deletion" on the default branch;
   - "main: tested" on the default branch: required status check
     `ci passed` from GitHub Actions, branches must be up to date. This
     repository lets the admin role bypass it (ADR 0002, "What 'main is
     what was tested' means"); leave the bypass out if every change should
     go through a pull request;
   - "release tags: never moved or deleted" on `v*`.
5. `automerge.yml` runs only in `pipiobjo/opnsense-api-go`; change the
   repository name in its `if:` for your copy.
6. Repository variable `WD_WATCH` (Settings -> Secrets and variables ->
   Actions -> Variables): the workflows of other repositories the watchdog
   watches, as space-separated `owner/repo:workflow.yml` pairs, for example
   `you/opnsense-api-spec:pipeline.yml you/opnsense-api-spec:watchdog.yml`.
   Without it a copy watches only its own `spec-update.yml`.
7. Watch the repository's issues (Watch -> Custom -> Issues); that is how
   the watchdog reaches you.
8. Run `ci.yml` by hand once and read the summary; then `spec-update.yml`.
   The schedules (`spec-update.yml` at 10:17 UTC, after the spec's daily
   run; `watchdog.yml` at 17:47 UTC) can be moved.

## Pins

| File | Names | Moved by |
|---|---|---|
| `tools/ci/spec-ref` | the spec commit of the test VM action and the watchdog script | `spec-update.yml`, only to a commit whose `promote.yml` passed |
| `tools/ci/catalog-ref` | the data `ci.yml` tests with (`catalog-v1-<data_id>`) | `spec-update.yml`, to the state the spec's pointer release `catalog-v1` names (`tools/ci/catalog-ref.sh latest`) |

Both move together on one branch `spec-pin/<spec>-<data_id>-<main>`;
`ci.yml` runs there, and its pull request has auto-merge on: GitHub
rebases it onto `main` once `ci passed` is green. The next
`spec-update.yml` run merges a passed one that is still open, reruns the
failed jobs once when it did not pass, deletes the branch after a second
failure, and removes a pin branch (and its pull request) that a newer
`main` left behind. To move a pin by hand, run
`tools/ci/spec-ref.sh set <sha>` or `tools/ci/catalog-ref.sh set
catalog-v1-<data_id>`, run the integration tests on all three series
(CONTRIBUTING.md), and push.

## Tolerance files

Changes to these need a reason and evidence from two runs:

- `tools/ci/skip-allowlist.txt`: the only tests that may skip.
- `test/integration/apply-failures.json`: apply endpoints that cannot work
  on the isolated VM, per series, with the text their failure must
  contain (`match`). An entry whose apply works fails the run.
- `test/integration/tested-floor.txt`: the minimum number of resources
  written and read back per series.
- `tools/ci/coverage-floor.txt`: coverage floors with their margin.

A new series needs no entry in the last two files: it takes those of the
newest older series (docs/testing.md).
