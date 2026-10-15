# Security policy

The Pit holds people's credentials, so security reports are the most useful contribution there is.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub:
**Security → Report a vulnerability** on this repository
(<https://github.com/OscillatingMonkey/the-pit/security/advisories/new>).

Include what you found, the version (`pit --version`) and platform, and the smallest steps that
show it. Encrypted vault files are fine to share only if they hold nothing real.

You can expect an acknowledgement within a week and a fix or a plan within 30 days for anything
serious. Reporters are credited in the release notes unless they would rather not be.

## Supported versions

Only the newest release (and `main`) receives fixes while The Pit is at 0.x.

## What is in scope

- Reading a secret value without the owner's keys and approval: from the vault files, the agent,
  its socket, backups, bundles, logs, temporary files or a process listing.
- Getting the agent to act without the approval its policy requires (pushes to protected channels,
  reveals, `pit run`, exports), or an AI (MCP) client getting anything that returns a value.
- Rolling the vault or its audit log back, or editing either, without being detected.
- Weaknesses in how cryptography is used (key derivation, nonces, authenticated data, key slots,
  recovery shares).
- A destination writing outside where it was told to, or a backup/bundle restore doing so.

## Out of scope

- Someone who already has the unlocked pit's approvals (Touch ID, the password or an authenticator
  code) using them.
- Malware running as the same user *while the pit is open*: it can ask the agent for what an
  open session allows. [docs/security.md](docs/security.md) describes this limit and what reduces it.
- Values once delivered to a service or a `.env` file you asked for.

## Status

The Pit has **not** had an independent audit. It composes audited RustCrypto primitives
(Argon2id, XChaCha20-Poly1305, HKDF-SHA256, X25519 sealed boxes) and does not implement its own.
How it protects secrets, and its known limits, are written down in
[docs/security.md](docs/security.md).
