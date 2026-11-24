# 0004: A configured CA replaces the system roots

Status: accepted 2026-11-24

## Context

`TLS.CAFile` and `TLS.CAPEM` name the CA that signs the firewall's
certificate, typically an internal PKI. Until this decision the client
added those certificates to the system roots. A firewall with a public
DNS name (common with the ACME plugin) could then also be impersonated
with any publicly trusted certificate for that name, although the operator
had named one CA. The review of 2026-11-24 (DEV-4, SEC-7) asked to decide
this before the first release, since changing it later changes behaviour
for users.

## Decision

With `CAFile` or `CAPEM` only the configured certificates are trusted
(`x509.NewCertPool`); both may be set and are combined. Without any TLS
setting the system roots are used, as before. Whoever wants the public
roots as well puts them into the PEM themselves.

## Consequences

- A firewall whose certificate comes from a public CA and that has
  `CAFile` set to an internal CA now fails to connect; the remedy is to
  drop `CAFile` (system roots) or to name the public CA.
- `TestCAReplacesSystemRoots` makes a certificate a system root in a child
  process (`SSL_CERT_FILE`) and shows it is trusted by default and refused
  when another CA is configured. It failed against the old behaviour.
