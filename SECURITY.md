# Security policy

## Intended use

This repository is an educational, defensive-security lab. Run it only on
systems, registries, packages, and accounts you own or are explicitly
authorized to test. It is not a supported covert-control product.

The supported configuration is the current `main` branch with a supported
Node.js LTS release. Historical revisions receive no security fixes.

## Reporting a vulnerability

Use the repository's private security-advisory feature when available. Do not
open a public issue containing an exploit, access token, private registry URL,
or captured task/result data. Include the affected revision, configuration,
reproduction steps, impact, and a proposed mitigation if known.

If a credential may have been exposed, revoke or rotate it immediately before
continuing the report. Tokens in this lab should be short-lived and scoped to
one disposable package.

## Security boundaries

- Public npm use and non-loopback plaintext HTTP require explicit opt-ins.
- Path operations are confined to `filesystemRoot`, including through
  symlinks. Set this to a dedicated directory, never `/`.
- Desktop-affecting operations and environment-value disclosure are disabled
  by default.
- State, logs, and downloaded files are written with private permissions on
  POSIX systems.
- The local lab binds the registry to loopback and shares a lab-only token
  between the two sides. That token is a lab convenience, not a production
  credential-distribution design.

See [`docs/operations.md`](docs/operations.md) for deployment, rotation,
backup, upgrade, and incident procedures.
