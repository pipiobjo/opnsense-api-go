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

- `capability`: load the data, resolve each installed package to the
  fragment that describes it, check values (type, static options, required
  fields).
- `opnsense`: detect the firewall, generic settings and entry operations,
  apply, read-back.
- `transport`: HTTP/2, TLS that is always verified, error mapping.

A new OPNsense release changes data, not code. Typed structs per plugin can
be generated on top later, for people writing Go by hand; the provider does
not need them.

Rules that follow from OPNsense's behaviour (each observed on a test VM,
2026-11-15):

1. Nothing is sent that the resolved version does not have: OPNsense
   answers `"saved"` for unknown keys, nested ones included, and ignores
   them.
2. Every `Add` and `Set` is read back and compared; lists are compared as
   sets. This also covers versions the data has only assumed.
3. `Set` checks first that the entry exists: for an unknown UUID OPNsense
   creates a new entry under that UUID, which would silently undo a
   delete. A get of an unknown UUID returns `[]`.
4. GET requests carry no body and no `Content-Type` (HTTP 400 otherwise);
   only they are retried.
5. Resolution order for packages: the exact combination; the same version
   seen on other frameworks with one identical fragment; the nearest older
   core of the series; the newest fragment of the series (assumed). A core
   version that is not in the data uses another hotfix revision of the same
   release, else the nearest core of the series. Every assumption is a
   warning; `Refuse` turns them into errors.

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

- Unit tests with a fake firewall that reproduces the recorded behaviour
  (unknown keys ignored, `[]` for unknown UUIDs, creation by set); every
  rule above has a test that fails when the rule is removed.
- Integration on a throwaway OPNsense 26.7.9_1 with os-frr 2.1: exact
  detection, a full OSPF neighbor cycle including the set after delete,
  settings set and restored.
