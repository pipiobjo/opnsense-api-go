# 0003: Consumers embed one capability data state at build time

Status: accepted 2026-11-24

## Context

The client carries no capability data (ADR 0002): whoever ships a product
built on it ships the data. The spec repository's requirements (P3) also
allowed the provider to load a newer attested state at run time. That
would need a download, checksum, attestation and unpacking path in Go in
every consumer (the provider and the MCP server); verifying a Sigstore
attestation without the `gh` CLI needs a large dependency, and the client
is standard library only. Two copies of security-critical code would
appear, and the easiest one to get wrong (skipping the attestation) is
the one most likely to be dropped. The review of 2026-11-24 (ARC-8, CON-2)
asked for a decision; the user decided on 2026-11-24: embedded only.

## Decision

1. A consumer embeds exactly one immutable data state,
   `catalog-v1-<data_id>`, at build time. Loading data at run time is not
   supported (dropped from P3).
2. The build step is this repository's `tools/ci/catalog.sh`, with the
   tag pinned: it downloads without credentials, checks `SHA256SUMS` and
   the build provenance attestation (only the spec's publishing workflow
   on `main` counts), checks that the tag's `data_id` is the one inside,
   unpacks, and fails on any error. It needs `curl`, `gh`, `jq`, `zstd`.
3. The consumer embeds the directory with `go:embed` and loads it with
   `capability.Load`:

   ```go
   // CATALOG_TAG=catalog-v1-<data_id> tools/ci/catalog.sh internal/data/catalog
   //go:embed catalog
   var catalogFS embed.FS

   func capabilities() (*capability.Set, error) {
       sub, err := fs.Sub(catalogFS, "catalog")
       if err != nil {
           return nil, err
       }
       return capability.Load(sub)
   }
   // opnsense.New(ctx, opnsense.Config{..., Capabilities: set})
   ```

   It reports `Instance().DataID` (and `Catalog.DataID` before connecting)
   to its users.
4. The pinned state moves like this repository's own pin
   (`tools/ci/catalog-ref`, ADR 0002 point 6): automation proposes the
   newest state on a branch, the consumer's tests run against it, and
   `main` moves only when they passed. `catalog-ref` in this repository
   names the newest state the client's own suite passed on, so a consumer
   that pins the same state embeds data the client was tested with.

## Consequences

- No run-time download code in any consumer; the attestation is checked
  once, in the build, by one script.
- A new OPNsense release reaches users of the provider with a provider
  release. With older data the client keeps working on a newer firewall
  of the same series (nearest data, read-back of every write), so that
  release is not urgent.
- `TestLoadFromEmbed` loads the test data through `embed.FS` and `fs.Sub`,
  the path this recipe uses.
