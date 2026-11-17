# Security

## Reporting a problem

Please report security problems privately through GitHub: **Security ->
Report a vulnerability** in this repository. Do not open a public issue.

You can expect an acknowledgement within a week. This is a volunteer
project without a support contract; fixes are made on a best-effort basis.

## What is in scope

- Anything that makes the client send something other than what the caller
  asked for, or report success for a change the firewall did not make.
- Credentials: a way for the API key or secret to end up in an error, a
  log or a request to another host.
- TLS: a way to talk to a firewall whose certificate was not verified,
  other than the explicit `TLS.InsecureSkipVerify` (which always carries a
  warning).
- The capability data handling: a way for crafted data to cause anything
  beyond a refused load.

## What is not

Bugs in OPNsense itself; report those to the OPNsense project.

## Dependencies

The module uses the Go standard library only; there is no third-party
code in what you build. Its SBOM (attached to each release) therefore
lists the module and the Go release.

CI uses GitHub's own actions and `jdx/mise-action`, pinned by commit
hash, and the official CycloneDX generator for Go (`cyclonedx-gomod`) in
the digest-pinned `golang` image, isolated in rootless Podman. Dependabot
alerts are on, and Dependabot proposes action updates monthly.
`tools/ci/vulncheck.sh` (govulncheck) runs in CI, before every release and
whenever the spec publishes new data: it fails on a vulnerability that the
client's code reaches and that has a fix (a newer Go patch release, which
CI picks up by itself), and warns about one without a fix yet.

Review of 2026-11-17 against the OSV database: no known vulnerability;
the one finding for Go 1.27.3 (HTTP server, not used by the client) is
fixed in 1.27.4, which CI uses. Build the client with a current Go patch
release.
