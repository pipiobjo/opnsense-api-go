# opnsense-api-go

A Go client for the [OPNsense](https://opnsense.org) API that adapts to the
firewall it talks to. It detects the core version and the installed
plugins, looks up what exactly that combination offers in the
[capability data](https://github.com/pipiobjo/opnsense-api-spec/blob/main/docs/capabilities.md)
of [opnsense-api-spec](https://github.com/pipiobjo/opnsense-api-spec), and
refuses to send a resource, field or value that version does not have.
After every write it reads the object back and compares.

Why this matters: OPNsense silently ignores keys it does not know and
answers `"saved"`. A client that sends a field from another version, or a
misspelled one, gets success and nothing happens. This client turns that
into an error before anything is sent, and catches the rest by reading
back.

Not an official OPNsense project. Status: **pre-release**, the API may
still change; see [Status](#status).

## Use

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

ospf, err := c.Settings("quagga/ospfsettings")
err = ospf.Set(ctx, opnsense.Values{"enabled": true, "routerid": "192.0.2.1"})

err = c.Apply(ctx) // activate: each pending apply endpoint once
```

Resources are named as in the capability data: `<module>/<controller>` for
settings, `<module>/<controller>#<model path>` for entry lists. `Values`
maps field paths to `bool`, `int64`, `string` or `[]string` (list fields);
the wire encoding (`"0"`/`"1"`, comma-separated lists, option maps on read)
is the client's job.

## Behaviour

| Situation | Result |
|---|---|
| Resource not installed or not in this version | `*ErrNotAvailable` with the versions that have it |
| Field not in this version (or misspelled) | `*ErrFieldNotAvailable` with the versions that have it; nothing is sent |
| Wrong type; value not in a complete option list; a field the firewall or the endpoint sets itself | `*ErrInvalid`; nothing is sent |
| Firewall rejects the values (including missing required ones) | `*ErrValidation` with the firewall's message per field |
| Firewall says "saved" but reads back differently | `*ErrNotApplied` with sent and read values (after `Add` the ID is returned too: the entry exists). Each difference carries a `Cause` from the capability data: `custom-write` (the field's type converts values on write), `custom-save` (the firewall stores the resource through its own code, which may drop values that do not apply to the rest of the entry), or empty (unexplained). It stays an error either way |
| Entry does not exist | `ErrNotFound`; `Set`, `Toggle` and `Delete` check through the list first, because OPNsense would create a new entry under an unknown ID, and some plugins answer an unknown ID with a blank template |
| One field of an object has an unexpected shape | the other fields are returned together with `*ErrDecode` |
| An apply endpoint does not report ok | `*ErrApply`; the endpoint stays pending |
| Key or secret wrong / privilege missing | `ErrUnauthorized` / `ErrForbidden`; credentials never appear in errors or logs |

Detection resolves each installed package to the data that describes it:
exact when the pipeline has seen the combination; otherwise, by default,
the nearest data of the same series. Another hotfix revision of a known
release, or a known plugin version seen on another core, is a note in
`Instance().Notes` (usual, nothing to do). A release or plugin version the
data has never seen is a warning in `Instance().Warnings`.
`UnknownVersion: opnsense.Refuse` turns both into errors. Read-back still
protects every write.

### Capability data

The client carries no data ([ADR 0002](docs/adr/0002-operation-without-maintenance.md)).
Get it from the release `catalog` of opnsense-api-spec and verify it:

```sh
gh release download catalog -R pipiobjo/opnsense-api-spec -D catalog
cd catalog && sha256sum -c SHA256SUMS
gh attestation verify SHA256SUMS -R pipiobjo/opnsense-api-spec
tar --zstd -xf capabilities.tar.zst
```

The `catalog` release is not published yet: its format is final only
after the planned OpenTofu provider has used it. Until then,
`tools/ci/catalog.sh DIR` builds the same data from the spec repository's
published pipeline state (it needs Go, `curl`, `zstd` and `jq`).

You do not have to update it for every OPNsense release: with older data
the client keeps working on a newer firewall and refuses only fields and
resources it does not know yet. Update it when you need one of them.

What the client deliberately does not check before sending, because the
data cannot know it reliably: required fields (controllers fill some of
them), option lists of field subclasses (they add options at run time),
and anything that refers to other objects. The firewall's own validation
answers these as `*ErrValidation`.

Entry IDs are usually UUIDs, but not always (`wan`, `bogons`, hashes).
IDs may contain letters, digits, `_`, `-` and `.`, not start with a dot;
anything else is refused before a request is built.

`Apply` activates pending changes of all resources; `Entries.Apply` and
`Settings.Apply` only those of one resource. A write that lands while an
apply runs stays pending. `Call` reaches any other API endpoint (service
actions, diagnostics) without checks or read-back.

### TLS

Verification is on by default against the system roots. Alternatives,
exactly one of them:

- `TLS.CAFile` / `TLS.CAPEM`: the CA that signed the firewall's certificate.
- `TLS.PinSHA256`: the SHA-256 of the firewall's certificate; the right
  choice for the self-signed certificate OPNsense creates.
- `TLS.InsecureSkipVerify`: no verification. Anyone on the network path
  can read the key and secret and change the firewall. Every client
  created with it carries `opnsense.InsecureWarning` in
  `Instance().Warnings`.

Redirects are never followed, the URL may not contain credentials, and only
GET requests are retried (on connection errors, never on certificate
errors).

## Status

| Part | State |
|---|---|
| Transport, wire encodings, detection, resolver, value checks, settings, entry lists, toggle, apply, read-back | implemented; unit tests against a fake firewall built from recorded behaviour (each rule has a test that fails without it); integration test against OPNsense 26.7.9 with 70 plugins: 311 resources, 359 checks, 0 failures |
| Integration tests in CI on the newest release of each series | next |
| Typed Go structs per plugin | not planned |

Supported: OPNsense 25.7 and newer, core and official plugins, as far as the
capability data covers them. Not yet tested by integration runs: 25.7 and
26.1 (the resolver is unit-tested against the data of all 34 releases).

## Tests

```sh
go test ./...                       # unit tests, fake firewall, real capability test data
go test -tags integration ./test/integration/   # against a throwaway VM, see the file header
```

The integration test exercises every resource the capability data marks as
verified on the VM's version: entry lists with the verified sample (add
and set with read-back, get, list, delete and check that the entry is
gone), settings by reading them and, where the contract test wrote them
successfully, writing one field back unchanged, and
every apply endpoint that became pending. It compares every field it
sent; the only tolerated difference is one the data explains with
`custom-save` on a field the contract test did not choose, and each is
logged. An apply endpoint whose service cannot run on the isolated VM (no
internet, no real hardware) answers HTTP 500 with OPNsense's message; that
is logged, any other failure fails. Samples that refer to something only
the contract test's instance had (a certificate, a device) are skipped with
the reason.

CI runs them on every push to `main` and every pull request, on the
newest verified release of each supported series (25.7, 26.1, 26.7) with
every plugin; `tools/ci/catalog.sh` gets the capability data.

Integration tests run only against a VM on `127.0.0.1` (the
[test VM action](https://github.com/pipiobjo/opnsense-api-spec/blob/main/docs/testvm-action.md)
of opnsense-api-spec); they refuse any other target.

## Layout

```
opnsense/              Client, Config, Entries, Settings, errors (public API)
opnsense/capability/   capability data model, resolver, value checks (usable on its own)
internal/transport/    HTTP, TLS, error mapping
test/integration/      tests against the throwaway VM
docs/adr/              decisions (0001 data-driven client, 0002 code only, no routine maintenance)
```

## Licence

BSD-2-Clause, see [LICENSE](LICENSE) and [NOTICE](NOTICE). OPNsense is a
registered trademark of Deciso B.V. Security problems: see
[SECURITY.md](SECURITY.md).
