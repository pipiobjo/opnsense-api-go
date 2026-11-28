# opnsense-api-go

A Go client for the [OPNsense](https://opnsense.org) API that adapts to the
firewall it talks to. It detects the core version and the installed
plugins, looks up what exactly that combination offers in the
[capability data](https://github.com/pipiobjo/opnsense-api-spec/blob/main/docs/capabilities.md)
of [opnsense-api-spec](https://github.com/pipiobjo/opnsense-api-spec), and
refuses to send a resource, field or value that version does not have.
After every write it reads the object back and compares (exceptions: see
[Behaviour](#behaviour)).

Why this matters: OPNsense silently ignores keys it does not know and
answers `"saved"`. A client that sends a field from another version, or a
misspelled one, gets success and nothing happens. This client turns that
into an error before anything is sent, and catches the rest by reading
back.

Not an official OPNsense project. Status: **pre-release**, the API may
still change; see [Status](#status).

## Use

Requires Go 1.26 or newer (`go.mod`); CI tests the oldest and the newest
supported Go release, and the minimum follows Go's own support window (the
two newest releases).

```go
c, err := opnsense.New(ctx, opnsense.Config{
	URL:    "https://fw.example.com",
	Key:    key,
	Secret: secret,
	TLS:    opnsense.TLS{PinSHA256: "3f2a..."}, // or CAFile, or the system roots
	CapabilityDir: "catalog",                 // unpacked release "catalog" of opnsense-api-spec, see below
})
if err != nil { ... }
for _, w := range c.Instance().Warnings { log.Print(w) } // guesses about versions the data has never seen

hosts, err := c.Entries("unbound/settings#hosts.host")
id, err := hosts.Add(ctx, opnsense.Values{"hostname": "nas", "domain": "example.com", "server": "192.0.2.10"})
cur, err := hosts.Get(ctx, id)
err = hosts.Set(ctx, id, opnsense.Values{"description": "storage"})
err = hosts.Delete(ctx, id)

rows, err := hosts.Rows(ctx) // every entry with its fields, one request
found, err := hosts.Find(ctx, opnsense.Values{"hostname": "nas", "domain": "example.com"}) // entries with these values

ospf, err := c.Settings("quagga/ospfsettings")
err = ospf.Set(ctx, opnsense.Values{"enabled": true, "routerid": "192.0.2.1"})

err = c.Apply(ctx) // activate: each pending apply endpoint once

info := hosts.Info()                            // fields, write-only/server-set/runtime-required, shared_with, verification
err = hosts.Check(opnsense.Values{"hostname": "nas"}) // every check of a write, nothing sent (plan time)
```

Resources are named as in the capability data: `<module>/<controller>` for
settings, `<module>/<controller>#<model path>` for entry lists, and
`<module>/<controller>#<model path>@<family>` where one entry list is
served by several families of endpoints (bind's primary and forward
domains). `Values`
maps field paths to `bool`, `int64`, `string` or `[]string` (list fields:
`multiple` option fields and every field with `list` in the data, such as
alias content or Kea DNS servers);
the wire encoding (`"0"`/`"1"`, lists joined by the data's separator,
option maps on read) is the client's job. Where the firewall keeps the
order of a list (`list.ordered`), reads return it in that order and a
write is compared in order; other lists compare as sets. To clear a field, set it to `nil` (sent as the empty
value; a provider does this for an attribute removed from the
configuration, since `Set` leaves fields it is not given unchanged).
Where the model has a default, the firewall may store that instead: the
read-back then reports the difference as `*ErrNotApplied`.

Reading entry lists: `List` returns the IDs, `Rows` every entry with its
fields (`[]Row{ID, Values}`), both from one search request; `Get` reads
one entry. `Find(values)` returns the entries whose fields equal all given
values, compared as the firewall stores them (the values are encoded as
`Add` would send them, lists compared as sets), also from one search. Use
it to find an entry by its natural key (hostname and domain of a host
override) and to avoid duplicates: OPNsense does not refuse two equal
entries. `Find` refuses fields the version does not have
(`*ErrFieldNotAvailable`), values that could not be sent and write-only
fields (`*ErrInvalid`), before sending anything. OPNsense's standard
search returns every field of an entry; a few controllers have their own
search with fewer columns: `Row.Values` then lacks those fields, and `Find`
reads such an entry with `Get` to compare them. The search shows stored
values; where the data says `Get` shows a field differently (a field the
endpoint stores transformed, such as base64 page content, or one whose
type renders its own text, such as an audit trail), `Rows` leaves it out
and `Find` compares it through `Get` (transformed fields cannot be
compared at all and are refused).

## Behaviour

| Situation | Result |
|---|---|
| Resource not installed or not in this version | `*ErrNotAvailable` with the versions that have it; `PluginsUnknown` when the API key may not read the plugin list |
| Any changing call with `Config.ReadOnly` | `*ErrReadOnly` (`Mode` set); nothing is sent |
| Firewall on a series newer than the data (e.g. 27.1 with data up to 26.7) | Readable with the newest data, marked as unverified in `Instance().Warnings`; every write is refused (`ErrReadOnly`) until the capability data covers the series, because a series change can change the framework the API comes from. With `UnknownVersion: Refuse`, or for a series older than the data, `New` fails with `*ErrSeriesNotInData` |
| Installed package older than every version of its series in the data | reading works; every write fails with `*ErrReadOnly`, because the data may describe fields that version lacks |
| Wrong resource kind, or an operation the resource does not have | `*ErrWrongKind`, `*ErrNoOperation` |
| Field not in this version (or misspelled) | `*ErrFieldNotAvailable` with the versions that have it; nothing is sent |
| Wrong type; value not in a complete option list; a field the firewall sets itself (`server_set`) or the endpoint sets (`forced`, `computed`); a field the firewall does not store (`volatile`) | `*ErrInvalid`; nothing is sent |
| Firewall rejects the values (including missing required ones) | `*ErrValidation` with the firewall's message per field in `Fields`; `Error()` names the fields only, since OPNsense's messages often quote the value |
| Firewall says "saved" but reads back differently | `*ErrNotApplied`; `Diffs` holds the sent and read values, `Error()` only the field names, since values may be secrets (after `Add` the ID is returned too: the entry exists). Each difference carries a `Cause` from the capability data: `custom-write` (the field's type converts values on write), `custom-save` (the firewall stores the resource through its own code, which may drop values that do not apply to the rest of the entry), or empty (unexplained). It stays an error either way. Not compared: write-only fields (passwords; the firewall never returns them) and fields the endpoint stores in another form (`transformed`, e.g. base64): for these only an empty read-back is reported |
| `Toggle` | the entry is read again; if `enabled` did not change, `*ErrNotApplied` |
| Entry does not exist | `ErrNotFound`. `Get`, `Set`, `Toggle` and the confirmation of `Delete` check existence first, because OPNsense's `set` would create a new entry under an unknown ID. One read of the entry decides where the controller answers an unknown ID with `[]`; the client measures that once per entry list (with an ID no entry has). Controllers that answer it with a blank template instead (some plugins) are checked through the search |
| Delete answered, but the entry is still listed | `*ErrStillExists` |
| Search answered with fewer rows than its total | `*ErrIncompleteList` (more rows than the total is accepted: 26.1's `firewall/d_nat` adds two uncounted anti-lockout rules) |
| A mutation answered in a way the client cannot interpret (e.g. "saved" without an ID) | `*ErrUnexpectedAnswer`; the mutation may have taken effect, so its apply endpoint is marked pending |
| A change was sent but its answer was lost, unreadable or HTTP 5xx | an error matching `ErrOutcomeUnknown` (the cause, e.g. `*HTTPError`, is kept); the change may be saved, so its apply endpoint is marked pending. After `Add` the ID is unknown: list the entries before adding again. A request that never reached the firewall is not this error |
| One field of an object has an unexpected shape | the other fields are returned together with `*ErrDecode` (for `Rows` and `Find` keyed `"<id> <field>"`) |
| An apply endpoint does not report ok | `*ErrApply`; the endpoint stays pending. With `AutoApply` the read-back comes first; both errors are returned |
| Key or secret wrong / privilege missing | `ErrUnauthorized` / `ErrForbidden`; credentials never appear in errors or logs. Only a missing firmware privilege lets `New` continue with the core alone; any other failure to read the plugin list fails `New` |

Detection resolves each installed package to the data that describes it:
exact when the pipeline has seen the combination; otherwise, by default,
the nearest older data of the same series. Another hotfix revision of a
known release, or a known plugin version seen on other cores, is a note in
`Instance().Notes` (usual, nothing to do). A release or plugin version the
data has never seen is a warning in `Instance().Warnings`; the data of the
nearest older known version is used, never newer data (a version older
than all data is read-only, see above). `UnknownVersion: opnsense.Refuse`
turns notes and warnings into errors, also for a package the data has but
not for this series. Read-back still protects every write.

### Read-only mode

`Config.ReadOnly` makes a client that reads but never changes the
firewall, for analysis tools or an assistant that helps configure without
touching anything. Every changing call (`Add`, `Set`, `Delete`, `Toggle`,
`Settings.Set`, `Apply`) returns `*ErrReadOnly` with `Mode` set
(`errors.Is(err, opnsense.ErrWriteRefused)`), before anything is sent. A
second check in the transport, with its own list, refuses every POST
except a search with a fixed body, and every GET or search whose path is
not a get or search operation of the capability data or listed in
`Config.ReadOnlyAllow` (before detection: only the two firmware paths
detection needs). So a mistake in the first check cannot send a write,
for POST and GET alike. `Call` may likewise only GET the get and search
operations; other endpoints (logs, status) must be listed in
`Config.ReadOnlyAllow`, because OPNsense does not mark which endpoints
change nothing, and some change state even on GET.

OPNsense cannot enforce this itself: a privilege grants URL patterns,
reading and writing together (of 195 privileges with API access in
26.7.9, none covers configuration read-only). Use both: an API user with
only the privileges the tool needs limits *where* it can act, read-only
mode makes sure it changes nothing there.

### Capability data

The client carries no data ([ADR 0002](docs/adr/0002-operation-without-maintenance.md)).
Get it from opnsense-api-spec and verify it. `catalog` is the newest
state; the release `catalog-v1` has no files, its notes name the newest
format-1 state (`data_id: <id>`);
`catalog-v1-<data_id>` is one fixed state that never changes (pin that
one when you embed the data):

```sh
gh release download catalog -R pipiobjo/opnsense-api-spec -D catalog
cd catalog && sha256sum -c SHA256SUMS
gh attestation verify SHA256SUMS -R pipiobjo/opnsense-api-spec \
  --signer-workflow pipiobjo/opnsense-api-spec/.github/workflows/pipeline.yml \
  --source-ref refs/heads/main
tar --zstd -xf capabilities.tar.zst
```

`Instance().DataID` reports the state in use; name it in bug reports.
`tools/ci/catalog.sh DIR` does the same (`CATALOG_TAG` pins a state,
e.g. `catalog-v1-<data_id>`) and fails if a check fails.

A product built on the client embeds one pinned state at build time and
does not load data at run time
([ADR 0003](docs/adr/0003-capability-data-embedded-at-build-time.md)):
run `CATALOG_TAG=catalog-v1-<data_id> tools/ci/catalog.sh <dir>/catalog`
as a build step, embed the directory with `//go:embed catalog`, and pass
`capability.Load(fs.Sub(embedded, "catalog"))` as `Config.Capabilities`.
`tools/ci/catalog-ref` names the newest state this client's own tests
passed on.

You do not have to update it for every OPNsense release: with older data
the client keeps working on a newer firewall of the same series and refuses
only fields and resources it does not know yet. Update it when you need one
of them, and before the firewall moves to a new series (until then the
client only reads on it).

What the client deliberately does not check before sending, because the
data cannot know it reliably: required fields (controllers fill some of
them), option lists of field subclasses (they add options at run time),
and anything that refers to other objects. The firewall's own validation
answers these as `*ErrValidation`. What the firewall offers for such a
field right now (its certificates, interfaces, aliases, other entries) is
read with `OfferedOptions(ctx, field)` on `Entries` (from the template of
a new entry) or `Settings`.

`Info()` describes a resource in the firewall's version, as copies a
consumer may keep: each field's type and kind, whether it is required,
*runtime-required* (the contract test found the firewall requiring it
although the model does not say so), write-only (`get` returns it empty,
so a change made elsewhere cannot be seen; from OPNsense 26.1.8 on a raw
search answer holds the stored value, which `Rows` leaves out), set by the
firewall, or converted on write. `Secret` says the value must not be
shown: every write-only field, and free-text fields named like a
password, secret, key, token, passphrase, community or credential (one
rule, `capability.Field.Secret`, for every consumer; it errs towards
hiding, and `opnsense/capability/testdata/secret/golden.txt` lists every
field it marks in one published data state); `SharedWith` names other resources on the same stored data (manage
it through one of them only); `Verified` is what the contract test found
on the data that describes this version (from this version, or from one
whose description is identical: `SameDefinition`), nil if nothing was
tested. A non-nil `Verified` does not mean written: `WriteVerified()` is
true only when read and write passed, the version is in the data (not
`Assumed`), and for settings a value was changed and restored;
`VerifiedOn()` names the release. A provider warns where `WriteVerified()`
is false. `Check(values)` runs every check a write would run without
sending anything, for plan time: fields, types, options, one value for a
single select, a required field left empty, and the `limits` the data
publishes: an integer range, a pattern and length, forbidden characters,
and the format of addresses and networks, host names, MAC addresses,
address and port, URLs and ports (with service names and ranges),
following the PHP code of each field class
([opnsense/capability/formats.go](opnsense/capability/formats.go)). The
spec's contract test writes these values to a real firewall and publishes
its verdicts; the client's tests replay all of them through `Check` and
require the same verdict. What only the firewall can know is left to it:
rules over several fields (gap `model-validation`), checks the data does
not describe (gap `validation-unknown`), whether an alias, a referenced
entry or a service name exists. In read-only mode
it still checks the
values and joins their errors with the `*ErrReadOnly`. `Fields()` and `Data()` return the raw
format-1 descriptions (copies, not a stable API); prefer `Info()`, whose
types belong to the client and do not change with the data format.

`c.Resources()` lists every resource this firewall has, as `Info`, by the
same rules `Entries` and `Settings` use (a server listing what it can
manage needs no rules of its own). `opnsense.Schemas(data)` works without
a firewall, for a provider schema before it is configured: per resource
the union of its fields over every version in the data, each described by
its newest variant, and every field whose type, kind or list-ness changed
between versions in `Conflicts` (for example os-frr's OSPF network `area`,
a text field that became a relation), so the consumer decides instead of
a silent pick.

Entry IDs are usually UUIDs, but not always (`wan`, `bogons`, hashes).
IDs may contain letters, digits, `_`, `-` and `.`, not start with a dot;
anything else is refused before a request is built.

`Apply` activates the changes this `Client` saved (its pending list);
`Entries.Apply` and `Settings.Apply` call the apply endpoint of one
resource unconditionally. The pending list lives only in the process: after
a failed apply, a new process (the next provider run) has nothing pending,
so it must call `Entries.Apply` or `Settings.Apply` for the resources it
manages to activate what an earlier run saved. When to apply in a provider:
[design.md, "Apply in a provider"](docs/design.md#apply-in-a-provider).
`Call` reaches any other API endpoint (service actions, diagnostics)
without checks or read-back.

A `Client` is safe for concurrent use. By default it runs one change or
apply at a time and reads never wait: parallel writes to OPNsense have not
been shown safe on a real firewall yet (design.md, rule 12).
`Config.ParallelWrites` lets changes to different models and applies run
together; a write that lands while an apply runs then stays pending. On
lists whose `get` answers unknown IDs with a template, `Get` reuses the
existence search for `Config.ExistsCacheTTL` (30 s by default; writes
always search afresh).

### TLS

Verification is on by default against the system roots. Alternatives,
exactly one of them:

- `TLS.CAFile` / `TLS.CAPEM`: the CA that signed the firewall's certificate.
  Only these certificates are trusted then, not the system roots
  ([ADR 0004](docs/adr/0004-custom-ca-replaces-system-roots.md)).
- `TLS.PinSHA256`: the SHA-256 of the firewall's certificate; the right
  choice for the self-signed certificate OPNsense creates.
- `TLS.InsecureSkipVerify`: no verification. Anyone on the network path
  can read the key and secret and change the firewall. Every client
  created with it carries `opnsense.InsecureWarning` in
  `Instance().Warnings`.

Redirects are never followed and the URL may not contain credentials.
Only requests that change nothing are retried: GET and the search POST
(whose body is fixed), after connection errors, cut-off answers and HTTP
502/503/504, with growing waits for about 30 seconds in total (long enough
for the web GUI to restart), never after certificate or authentication
errors and never beyond the context. A change is never retried; see
`ErrOutcomeUnknown`.

The built-in transport speaks HTTP/2. OPNsense's web server cuts large
answers over HTTP/1.1 (broken chunked encoding), so if you set
`Config.HTTPClient`, its transport must use HTTP/2 as well (for an
`http.Transport` with its own TLS settings: `ForceAttemptHTTP2: true`).
`Config.HTTPClient` replaces the built-in transport entirely; it cannot be
combined with the TLS settings (`New` refuses that), so a pin is never
dropped silently.

## Status

| Part | State |
|---|---|
| Transport, wire encodings, detection, resolver, value checks, settings, entry lists, toggle, apply, read-back | implemented; unit tests against a fake firewall built from recorded behaviour (each rule has a test that fails without it) |
| Integration tests, newest release of each series with every plugin | every written entry list also checked through `Rows`, `Find` and existence after delete; each series must reach its floor (`test/integration/tested-floor.txt`). CI runs them on every push and pull request against the data pinned in `tools/ci/catalog-ref`, and on every new data state before that pin moves; the numbers of each run are in its summary. Details in [docs/testing.md](docs/testing.md) |
| Typed Go structs per plugin | not planned |

Supported: OPNsense 25.7 and newer, core and official plugins, as far as the
capability data covers them. Only the newest release of each series is
tested by integration runs; older releases rely on the data and on
read-back.

## Tests

Unit tests run against a fake firewall that reproduces recorded OPNsense
behaviour, and against the real capability data of every release.
Integration tests run the client against a throwaway OPNsense VM with
every plugin, on the newest release of each supported series, on every
push and whenever opnsense-api-spec publishes new data. Coverage is
reported in CI with floors (`tools/ci/coverage-floor.txt`).

[docs/testing.md](docs/testing.md) says what has to be true for the client
to work, which test shows each part, how we know the tests can fail, the
measured results, and what is not tested. Requirements:
[opnsense-api-spec/docs/requirements.md](https://github.com/pipiobjo/opnsense-api-spec/blob/main/docs/requirements.md).

## Releases

No release has been tagged yet; until the first one (v0.1.0) a consumer
depends on a commit (a Go pseudo-version). A release is a version tag; the
Go module proxy serves it. Each release also has a GitHub release (`release.yml`, after the whole test suite
passed) with a software bill of materials (CycloneDX 1.6, made with the
official CycloneDX generator for Go), the unit test coverage report and
`SHA256SUMS`, all with a provenance attestation:

```sh
# once a release exists; <tag> is its version, e.g. v1.2.3
gh release download <tag> -R pipiobjo/opnsense-api-go -D rel && cd rel
sha256sum -c SHA256SUMS
gh attestation verify opnsense-api-go-<tag>.cdx.json -R pipiobjo/opnsense-api-go
```

The module depends on the Go standard library only, so the SBOM lists the
module and the Go release it was built and tested with. Versions below
v1 are pre-releases: the API may still change.

## Layout

```
opnsense/              Client, Config, Entries, Settings, errors (public API)
opnsense/capability/   capability data model, resolver, value checks (usable on its own)
internal/transport/    HTTP, TLS, error mapping
test/integration/      tests against the throwaway VM
tools/parallel.sh      local integration run on several throwaway VMs at once
docs/design.md         layers, request flow, behaviour rules, how to add one
docs/testing.md        what is tested, how we know it works, coverage, what is not tested
docs/adr/              decisions (0001 data-driven client, 0002 code only, no routine maintenance)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md): checks, integration tests on the
throwaway VM, and the rules for changes.

## Licence

BSD-2-Clause, see [LICENSE](LICENSE) and [NOTICE](NOTICE). OPNsense is a
registered trademark of Deciso B.V. Security problems: see
[SECURITY.md](SECURITY.md).
