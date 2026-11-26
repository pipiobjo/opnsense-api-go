# Contributing

Issues and pull requests are welcome. This project is maintained on a
best-effort basis; there is no promise of a response time.

Before you start, read [docs/design.md](docs/design.md) (layers, request
flow, the behaviour rules and how to add one) and the
[ADRs](docs/adr/). Security problems: [SECURITY.md](SECURITY.md), not a
public issue.

## Checks that need nothing but Go

```sh
mise install                       # Go toolchain from mise.toml
test -z "$(gofmt -l .)"
go vet ./... && go vet -tags integration ./...
go test -race -coverpkg=./... -coverprofile=unit.out ./...   # fake firewall, real capability test data
tools/ci/coverage.sh unit unit.out  # table per package, coverage/unit.html, floor check
```

`internal/mutation` (`TestMutantsAreKilled`) breaks the most important
checks one by one and runs their tests; when you change code a mutant
names, update its anchor in the table. What each test shows and which
claim it belongs to:
[docs/testing.md](docs/testing.md). A new test is named there under its
claim (`TestEveryTestIsDocumented` checks).

## Integration tests on a throwaway VM

The integration tests need an OPNsense instance on `127.0.0.1` and refuse
any other target. The test VM comes from
[opnsense-api-spec](https://github.com/pipiobjo/opnsense-api-spec)
(`tools/testvm.sh`, QEMU, ideally with KVM); its factory credentials and
the API key it creates exist only inside that VM. Never point the tests at
a real firewall. Repository settings and running a copy of the
automation: [docs/development.md](docs/development.md).

```sh
tools/ci/catalog.sh catalog        # the data pinned in tools/ci/catalog-ref; prints the test matrix
# in a checkout of opnsense-api-spec:
tools/testvm.sh start 26.7 --release 26.7.9 --plugins all   # writes .cache/vm/state.env
# back here, with url and keyfile from that state.env:
OPNSENSE_URL=<url> OPNSENSE_KEYFILE=<keyfile> OPNSENSE_PLUGINS=all \
OPNSENSE_CAPABILITIES=catalog go test -tags integration -count=1 -v ./test/integration/ | tee integration.log
tools/ci/skips.sh integration.log  # only the skips in tools/ci/skip-allowlist.txt
# in opnsense-api-spec:
tools/testvm.sh down
```

All three series at once, each on several fresh VMs (plugin groups, the
core on one of them, plus one VM per release that installs every plugin
together; about 2 GB of memory per VM, 9 to 12 VMs), with a checkout of
opnsense-api-spec next to this one (or `OPNSENSE_SPEC_DIR`):

```sh
tools/parallel.sh                  # VMs, tests, per-series floors and coverage, teardown
```

It prints a timing table and leaves logs and results in
`.cache/parallel/<time>/`; see [docs/testing.md](docs/testing.md),
"Parallel local runs".

`OPNSENSE_PLUGINS=all` says the VM has every plugin, so a test that needs
a missing one fails instead of skipping. Without hardware virtualisation
(`TESTVM_ACCEL=tcg`) set `TESTVM_SLOW` to the `slow` value `testvm.sh`
wrote to `.cache/vm/state.env` (6 by default): it stretches the request
timeouts as `testvm.sh` stretches its waits. CI takes it from the test VM
action's `slow` output.

Run it for each supported series (25.7, 26.1, 26.7) with the release the
matrix names. A change is done when all three pass; CI repeats this on
every push to `main` and every pull request.

## Rules for changes

- **Behaviour comes from the data where possible.** If OPNsense behaves in
  a way the source code explains, the rule belongs in the spec
  repository's derivation; the client then reads it from the data. The
  client codes only the API's own conventions ([design.md](docs/design.md),
  "Adding or changing a rule").
- **Every rule has a test that fails without it.** Teach the fake firewall
  (`opnsense/fake_test.go`) the behaviour, write the test, remove the rule
  once and watch the test fail.
- **No guessing.** What the data does not know is refused or reported,
  never filled in. A tolerated difference in a test comes from the data
  (`custom-save` and similar), never from a list of resource names.
- **Tests refer to versions, not fragment hashes**, so refreshing the test
  data after a generator change (`tools/testdata.sh`) needs no test change.
- **Version order** is `capability.CompareVersions`; the spec repository
  has the same function. Both are tested against the table the spec
  publishes (`version-order.json`, copied into the test data by
  `tools/testdata.sh`); a new case goes into that file in the spec.
- **Standard library only.** A new dependency needs a reason in an ADR.
- **Licence.** Contributions are under the BSD 2-Clause License
  ([LICENSE](LICENSE)); new files carry the SPDX header used in the
  existing files.
