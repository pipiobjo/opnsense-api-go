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
