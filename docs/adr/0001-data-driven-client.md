# 0001: A small runtime driven by capability data, not a generated client

Status: accepted 2026-11-15, implemented

## Context

A client generated from the OpenAPI document of one OPNsense release has
about 5,000 methods and describes exactly that release. Supporting every
release from 25.7 on would mean one client per release, or a superset that
does not know which version has what. Generated clients also ignore the
`x-opnsense-*` extensions that say how to write safely, and every release
would regenerate thousands of lines.

The API itself is uniform: about 190 entry lists and 180 settings models
follow the same few patterns, and nearly every value is a string on the
wire.

## Decision

A hand-written runtime of a few files, driven by the capability data of
opnsense-api-spec (format 1):

- `capability`: load the data the caller provides, resolve each installed
  package to the fragment that describes it, check values (type, static
  options).
- `opnsense`: detect the firewall, generic settings and entry operations,
  apply, read-back.
- `transport`: HTTP/2, TLS verified by default (an explicit, warned
  switch turns it off), no redirects, error mapping.

A new OPNsense release changes data, not code. Typed structs per plugin can
be generated on top later, for people writing Go by hand; the provider does
not need them.

Rules that follow from OPNsense's behaviour, each observed on a test VM
(26.7.9, 70 plugins, 2026-11-15):

1. Nothing is sent that the resolved version does not have: OPNsense
   answers `"saved"` for unknown keys, nested ones included, and ignores
   them.
2. Every `Add` and `Set` is read back and compared; lists as sets. Fields
   the endpoint stores in another form (`transformed` in the data) are
   skipped. This also covers versions the data has only assumed. A
   difference is always an error; where the data explains it
   (`custom-write` on the field, `custom-save` on the resource) the error
   says so. Example measured on 26.7.9: an interface assignment drops
   `dhcp6_request_dns` unless the IPv6 type is DHCPv6, so "0" reads back
   as "1"; OPNsense's interface model stores entries through its own
   `toLegacy` code.
3. Existence is decided by the list (search): for an unknown ID, `set`
   creates a new entry under that ID, `get` answers `[]` in most
   controllers but a blank template in some (os-nginx). So `Set`,
   `Toggle` and the confirmation after `Delete` ask the list.
4. Fields the firewall or the endpoint sets itself are refused before
   sending: `UniqueIdField`, `AutoNumberField`, `JsonAuditField`, and the
   `forced` and `computed` fields of the operation (bind domain types, the
   traffic shaper's pipe number, unbound's forward type).
5. Required fields and option lists of field subclasses are not checked
   locally: controllers fill some required fields, and subclasses such as
   `ServiceField` add options at run time. Only the core `OptionField`'s
   list is treated as complete. The firewall's validation reports the
   rest.
6. Answer shapes: option maps with keys `0..n` arrive as JSON lists; a
   model without fields as `[]`; apply success as `"status": "ok"` or
   `"result": "ok"` (anything else is `ErrApply`); some deletes answer
   nothing (`result-not-returned` in the data), then the list decides.
7. Entry IDs are not always UUIDs (`wan`, `bogons`, hashes): accepted are
   path-safe characters only, so no input can leave the API path.
8. GET requests carry no body and no `Content-Type` (HTTP 400 otherwise);
   only they are retried. Redirects are refused.
9. Resolution order for packages: the exact combination; the same version
   seen on other frameworks with one identical fragment; the nearest older
   core of the series; the newest fragment of the series (assumed). A core
   version that is not in the data uses another hotfix revision of the same
   release, else the nearest core of the series. Nearest data of a known
   release or plugin version is a note, a version the data has never seen
   a warning ([ADR 0002](0002-operation-without-maintenance.md));
   `Refuse` turns both into errors.

## Consequences

- No dependency outside the Go standard library so far.
- The client is as good as the capability data; read-back is the
  independent check, and the integration tests are a second consumer of the
  samples the spec repository verified.
- Values are typed only as bool, int64, string and list. Numbers that are
  not integers stay strings, so nothing is lost by rounding.
- Secrets are not marked in the data (OPNsense models do not mark them);
  write-only fields (`UpdateOnlyTextField`) are excluded from read-back.

## Evidence

- Independent review of the first draft (2026-11-15): 9 findings from
  path handling to an Apply race; each fixed with a test that fails without
  the fix.
- Unit tests with a fake firewall that reproduces the recorded behaviour
  (unknown keys ignored, `[]` for unknown UUIDs, creation by set); every
  rule above has a test that fails when the rule is removed.
- Integration on a throwaway OPNsense 26.7.9_1 with 70 plugins: every
  resource the data marks as verified (311), 359 checks, 0 failures, 3
  samples skipped as instance-specific. The run found rules 3 to 7; the
  overlays in rule 4 led to a change in the spec repository's derivation
  (`forced`, `computed`, `transformed`).
