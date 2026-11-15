# 0002: Operation without routine maintenance

Status: proposed 2026-11-15; to be implemented with the embedded data

## Context

OPNsense publishes a release roughly every two weeks, hotfix revisions in
between, and plugins update on their own schedule. A client that needs a
person for each of these falls behind within weeks. The spec repository
already turns each release into capability data without manual steps;
this client must take it from there the same way, and the routine upkeep of
the repository itself (dependencies, toolchain, actions) must not need a
person either.

Routine work that would otherwise fall to a person:

| Recurring work | Rate |
|---|---|
| New capability data (OPNsense release, hotfix, plugin update) | weekly or more |
| Dependency and action updates | monthly |
| Go toolchain security releases | monthly |
| Noticing that the automation itself stopped | rare, but silent |

## Decision

1. **Data updates run daily and end in a release** (`update.yml`, a few
   hours after the spec pipeline): fetch the `catalog` release; stop if its
   `SHA256SUMS` equals the recorded one; verify checksums and the build
   provenance attestation; validate against the JSON Schema; check the name
   lock (an identifier that disappears or changes its type class stops the
   update); run unit tests and the integration tests on the newest release
   of each series through the spec repository's test VM action; commit the
   data as the workflow bot; tag the next patch version (minor when
   resources or fields were added); publish release notes generated from
   the diff. Any failure commits nothing and opens one `update-failure`
   issue with the reason and what to do.
2. **Dependency updates merge themselves** after a waiting period (7 days,
   Dependabot `cooldown`) when CI is green; a separate workflow merges them
   on the successful CI run, without checking out their code with write
   permissions.
3. **The toolchain follows the latest stable Go** in CI; `go.mod` states
   only the minimum version. A security release of Go therefore reaches CI
   without a commit.
4. **The test VM action is pinned by commit** with the spec repository's
   version tag as comment, so Dependabot proposes updates when that
   repository tags a release.
5. **A watchdog** (daily, as in the spec repository) opens a `watchdog`
   issue when the update workflow has not succeeded for three days or is
   disabled, and closes it when it recovers.
6. **No secrets**: only the workflow's own token. Nothing to rotate.

What stays with a person, by design: a capability `format` change (the
spec repository publishes the old format for an overlap period), a name
lock violation (a removed or retyped field), a client code change when
OPNsense changes its API conventions (the daily integration tests show
it), and every action that speaks for the project outside its repository.

## Consequences

- A release of OPNsense reaches users of the client as a patch release
  within about a day, verified on a real instance of each series.
- The repository needs branch rules that let the workflow bot push data
  commits and tags, but nobody force-push or delete them.
- Measured cost per day: one integration run per series when the data
  changed (about 10 to 20 minutes each with KVM), nothing otherwise.
