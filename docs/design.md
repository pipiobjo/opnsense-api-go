# Design

How the client works inside, and the rules it follows. Why it is built
this way: [ADR 0001](adr/0001-data-driven-client.md) and
[ADR 0002](adr/0002-operation-without-maintenance.md). What it does for a
caller: the [README](../README.md#behaviour).

## Layers

| Package | Job | Knows about |
|---|---|---|
| `opnsense/capability` | load and check the capability data; resolve an installed package to the fragment that describes it; encode, decode and check values | the data format only; no network. Usable on its own |
| `opnsense` | detect the firewall; settings and entry operations; read-back; apply; errors | the data (through `capability`) and the API conventions |
| `internal/transport` | HTTPS with verified TLS, authentication, no redirects, retries of GET only, HTTP status to error | nothing about OPNsense resources |

Everything a new OPNsense version changes is data. The code holds only
the API's conventions (how a list is searched, how "saved" and
validation errors look, how an apply reports success), which have been
stable across all supported series.

## Creating a client

`New`:

1. Loads the data from `Config.Capabilities` or `Config.CapabilityDir`.
   The directory is opened with `os.OpenRoot`, so a symbolic link cannot
   lead outside it; file count and size are limited (`MaxPackages`,
   `MaxTotal`); the data is checked for internal consistency.
2. Builds the transport. `Config.HTTPClient` and TLS settings together are
   refused, so a certificate pin cannot be dropped by accident.
3. Detects the firewall: the core version and the installed packages from
   the firmware API. If the key may not read the plugin list, only a
   missing firmware privilege lets it continue with the core alone, and
   `ErrNotAvailable.PluginsUnknown` says so later.
4. Resolves each package to a fragment (rule 9 below). Notes and warnings
   go to `Instance()`; `UnknownVersion: Refuse` turns them into errors.

## A write, step by step

`Entries.Add` and `Set`, `Settings.Set`:

1. `writable`: refuse if the package is read-only (older than the data).
2. `op`: the operation exists for this resource kind and fragment
   (`ErrWrongKind`, `ErrNoOperation`).
3. `encode`: every field exists in this fragment, the value has the right
   type and, for a complete option list, an allowed value; fields the
   firewall sets (`server_set`), the endpoint sets (`forced`,
   `computed`) or does not store (`volatile`) are refused. Nothing has
   been sent when any of this fails.
4. Lock the model (one writer per model in this client).
5. For `Set` of an entry: confirm the entry exists through the list.
6. POST with the wrapper key; `result` maps the answer (`saved`,
   validation messages to `ErrValidation`, anything else to
   `ErrUnexpectedAnswer`).
7. Mark the resource's apply endpoint pending.
8. `readBack`: read the object and compare every sent field; lists as
   sets. Differences become `ErrNotApplied`, each with the cause the data
   gives (`custom-write`, `custom-save`, `transformed`) or none.
9. `finish`: with `AutoApply`, apply after the read-back; both results
   are returned.

Reads (`Get`, `List`) decode the firewall's shapes into `Values` and
return the decodable fields together with `ErrDecode` when one field has
an unexpected shape.

## Rules

Each rule comes from OPNsense behaviour measured on a test VM, and each
has a unit test against the fake firewall that fails when the rule is
removed.

1. **Nothing is sent that the resolved version does not have.** OPNsense
   answers `"saved"` for unknown keys, nested ones included, and ignores
   them.
2. **Every `Add` and `Set` is read back and compared**, lists as sets.
   This also covers versions the data has only assumed. A difference is
   always an error; where the data explains it (`custom-write` on the
   field, `custom-save` on the resource) the error says so. Example: an
   interface assignment drops `dhcp6_request_dns` unless the IPv6 type is
   DHCPv6, because OPNsense stores interface entries through its own
   `toLegacy` code.
3. **Existence is decided by the list.** For an unknown ID, `set` creates
   a new entry under that ID; `get` answers `[]` in most controllers but
   a blank template in some (os-nginx). So `Set`, `Toggle` and the
   confirmation after `Delete` ask the list, and `Get` asks it when the
   answer is incomplete or equals the blank template.
4. **Fields set by the firewall or the endpoint are refused** before
   sending: `server_set` fields, and the `forced` and `computed` fields of
   the operation (bind domain types, the traffic shaper's pipe number,
   unbound's forward type).
5. **Required fields and option lists of field subclasses are not checked
   locally.** Controllers fill some required fields, and subclasses such
   as `ServiceField` add options at run time. Only the core
   `OptionField`'s list is treated as complete. The firewall's validation
   reports the rest.
6. **Answer shapes.** Option maps with keys `0..n` arrive as JSON lists;
   a model without fields as `[]`; apply success as `"status": "ok"` or
   `"result": "ok"` (anything else is `ErrApply`); some deletes answer
   nothing (`result-not-returned` in the data), then the list decides. A
   search may return more rows than its total (26.1's `firewall/d_nat`
   adds two uncounted anti-lockout rules), but never fewer
   (`ErrIncompleteList`).
7. **Entry IDs are not always UUIDs** (`wan`, `bogons`, hashes). Only
   path-safe characters are accepted, so no input can leave the API path.
8. **GET requests carry no body and no `Content-Type`** (HTTP 400
   otherwise); only they are retried. Redirects are refused.
9. **Resolution order for packages**: the exact combination; the same
   version seen on other frameworks with one identical fragment (a note);
   the nearest older core of the series (a note); for a version the data
   has never seen, the data of the nearest older known version of the
   series (a warning). Never newer data than the installed version: a
   package older than all data of its series uses the oldest data
   read-only (`ErrReadOnly`). A core version not in the data uses another
   hotfix revision of the same release, else the nearest older core of
   the series; a core older than the data of its series is read-only too.
   A series the data does not cover fails `New` (`ErrSeriesNotInData`):
   a series change can change the framework, so it is not guessed.
   Versions are ordered by `CompareVersions`, the same function with the
   same test table as in opnsense-api-spec.
10. **Read-back exceptions**: `write_only` fields are not compared (never
    returned); volatile fields are refused before sending (never stored);
    transformed fields only must not come back empty. `Toggle` reads the
    entry again and fails if `enabled` did not change.

## Adding or changing a rule

1. Reproduce the behaviour on the throwaway VM with raw calls
   (`test/integration/recorded_test.go` shows how; it bypasses the client
   so the client's own checks cannot hide what OPNsense does). Find the
   cause in the OPNsense source.
2. If the cause can be derived from the source, the rule belongs in the
   spec repository's derivation, and the client reads it from the data.
   Prefer this: it keeps working for plugins nobody has looked at. A rule
   in the client is only for conventions of the API itself.
3. Teach the fake firewall (`opnsense/fake_test.go`) the behaviour and
   write a test that fails without the rule. Remove the rule once and
   watch the test fail.
4. Run the integration test on all supported series (see
   [CONTRIBUTING.md](../CONTRIBUTING.md)).
5. Add the rule here and, if a caller sees it, to the README's behaviour
   table.

## Tests

| Layer | What it proves | Where |
|---|---|---|
| Unit tests with a fake firewall | each rule; error mapping; no request before a refused write | `opnsense/*_test.go` |
| Data tests | the resolver and value checks against real capability data of all releases (trimmed to core and os-frr OSPF; `tools/testdata.sh`) | `opnsense/capability/*_test.go` |
| Fuzz targets | answer decoding, data loading, IDs and paths never panic or escape; generic, so they need no change when the API changes | `*/fuzz_test.go` |
| Recorded behaviour | OPNsense still behaves as the rules assume, with raw calls | `test/integration/recorded_test.go` |
| Integration | every resource the data marks verified, on a VM with every plugin, per series | `test/integration/integration_test.go` |
