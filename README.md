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
	CapabilityDir: "catalog",                 // unpacked release "catalog" of opnsense-api-spec
})
if err != nil { ... }
for _, w := range c.Instance().Warnings { log.Print(w) } // assumptions about unknown versions

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
| Wrong type, value not among the static options, required field missing on `Add` | `*ErrInvalid`; nothing is sent |
| Firewall rejects the values | `*ErrValidation` with the firewall's message per field |
| Firewall says "saved" but reads back differently | `*ErrNotApplied` with sent and read values (after `Add`, the UUID is returned too: the entry exists) |
| Entry does not exist | `ErrNotFound`; `Set` checks first, because OPNsense would create a new entry under an unknown UUID |
| Key or secret wrong, or privilege missing | `ErrUnauthorized`; credentials never appear in errors or logs |

Detection resolves each installed package to the data that describes it:
exact when the pipeline has seen the combination; otherwise, by default,
the nearest data of the same series with a warning in
`Instance().Warnings` (`UnknownVersion: opnsense.Refuse` makes that an
error). A newer core hotfix than the data, or a plugin built after the last
data update, is the usual case. Read-back still protects such writes.

TLS verification cannot be turned off. For a self-signed firewall
certificate, pin it (`TLS.PinSHA256`, the SHA-256 of the certificate).
Only GET requests are retried (on connection errors); mutations never are.

## Status

| Part | State |
|---|---|
| Transport, wire encodings, detection, resolver, validation, settings and entry lists, apply, read-back | implemented, unit-tested against a fake firewall built from recorded responses, and integration-tested on a throwaway OPNsense 26.7.9 |
| Embedded capability data (no `CapabilityDir` needed), its provenance and the name lock | next |
| Integration tests for every verified resource on the newest release of each series | next |
| Daily data update and releases | after that |
| Typed Go structs per plugin | later, optional |

Supported: OPNsense 25.7 and newer, core and official plugins, as far as the
capability data covers them.

## Tests

```sh
go test ./...                       # unit tests, fake firewall, real capability test data
go test -tags integration ./test/integration/   # against a throwaway VM, see the file header
```

Integration tests run only against a VM on `127.0.0.1` (the
[test VM action](https://github.com/pipiobjo/opnsense-api-spec/blob/main/docs/testvm-action.md)
of opnsense-api-spec); they refuse any other target.

## Layout

```
opnsense/              Client, Config, Entries, Settings, errors (public API)
opnsense/capability/   capability data model, resolver, value checks (usable on its own)
internal/transport/    HTTP, TLS, error mapping
test/integration/      tests against the throwaway VM
docs/adr/              decisions
```

## Licence

BSD-2-Clause, see [LICENSE](LICENSE) and [NOTICE](NOTICE). OPNsense is a
registered trademark of Deciso B.V. Security problems: see
[SECURITY.md](SECURITY.md).
