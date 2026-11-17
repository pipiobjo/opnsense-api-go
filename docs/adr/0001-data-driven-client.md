# 0001: A small runtime driven by capability data, not a generated client

Status: accepted 2026-11-15, implemented

## Context

A client should work with every OPNsense release from 25.7 on, core and
plugins, without a code change per release, and it should not let a
write fail silently: OPNsense answers `"saved"` for keys it does not know
and ignores them.

A client generated from the OpenAPI document of one release has about
5,000 methods and describes exactly that release. Generated clients also
ignore the `x-opnsense-*` extensions that say how to write safely, and
every release would regenerate thousands of lines.

The API itself is uniform: about 190 entry lists and 180 settings models
follow the same few patterns, and nearly every value is a string on the
wire.

## Alternatives considered

| Option | Why not |
|---|---|
| Generated client per release (oapi-codegen or similar) | one client per release, or a superset that cannot tell which version has what; no read-back, no version checks; thousands of generated lines per release to review |
| Generated typed structs per plugin over all versions | same knowledge problem (a field exists only in some versions), and a struct change for every plugin release; useful later as a convenience layer, not as the core |
| Hand-written resources, like existing providers | the approach that does not scale: every plugin and every version is manual work, which is what this project exists to avoid |
| No data, discover at run time from the firewall | the API has no self-description; options, defaults and versions would have to be guessed |

## Decision

A hand-written runtime of a few files, driven by the capability data of
opnsense-api-spec (format 1). The data says what a firewall of a given
version offers; the code only knows the API's conventions. Layers,
request flow and the rules derived from OPNsense's behaviour are in
[design.md](../design.md).

- `capability`: load the data the caller provides, resolve each installed
  package to the fragment that describes it, check values.
- `opnsense`: detect the firewall, generic settings and entry operations,
  apply, read-back.
- `transport`: HTTP/2, TLS verified by default (an explicit, warned
  switch turns it off), no redirects, error mapping.

## Consequences

- A new OPNsense release changes data, not code.
- No dependency outside the Go standard library.
- The client is as good as the capability data; read-back is the
  independent check, and the integration tests are a second consumer of
  the samples the spec repository verified.
- Behaviour that the data can describe is derived in the spec repository,
  not coded here (for example `server_set`, `write_only`, `custom-save`).
- Values are typed only as bool, int64, string and list. Numbers that are
  not integers stay strings, so nothing is lost by rounding.
- Secrets are not marked in the data (OPNsense models do not mark them);
  only `write_only` fields are known.

## Evidence

- Independent review of the first draft (2026-11-15): 9 findings from
  path handling to an Apply race; each fixed with a test that fails without
  the fix.
- Second independent review (2026-11-16): 11 findings (toggle without
  read-back, complete blank templates, volatile and transformed fields,
  series and version fallback, an own HTTP client dropping the pin,
  AutoApply order, detection fallback, untyped errors, data directory
  links and size, tests that could not fail); each fixed with a test seen
  failing first.
- Integration on a throwaway OPNsense 26.7.9_1 with 70 plugins
  (2026-11-15): 311 resources, 359 checks, 0 failures, 3 samples skipped
  as instance-specific. The run found rules 3 to 7 of design.md; the
  overlays in rule 4 led to a change in the spec repository's derivation
  (`forced`, `computed`, `transformed`).
- 26.1's `firewall/d_nat` search returns two anti-lockout rows it does not
  count (measured on 26.1.11_10, 2026-11-16): a search may return more
  rows than its total.
- Local integration runs on fresh VMs with every plugin, spec data 0.9.3
  (2026-11-17): 25.7.11_9 299 resources, 303 checks passed; 26.1.11_10
  307 / 311; 26.7.9_3 314 / 318; 0 failures. The only tolerated
  differences were `custom-save`, each logged.
