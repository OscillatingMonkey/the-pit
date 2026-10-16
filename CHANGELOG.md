# Changelog

## 0.1.1 — 2026-10-15

Security hardening, public assurance, and a friendlier console.

- Console: Tab completes commands, flags and project, channel, secret and destination names;
  `help COMMAND`; a mistyped command gets suggestions and a list of common tasks (on the command
  line too). `view`, `show` and `get` work for `reveal`, `list` for `ls`, `delete`/`remove` for `rm`.

- Adding or changing a destination now always needs approval, on unprotected channels too.
- Reveals, `pit run`, exports and pushes are refused if their audit-log entry cannot be written; a
  push is logged before anything is sent.
- The wrong-guess counter is also kept in the Keychain and in the agent's memory.
- The agent caps request size and simultaneous connections.
- `pit run`'s temporary folder is created exclusively; AI scan results no longer include value lengths.
- `rustls` 0.23.46 (RUSTSEC-2026-0346 to -0349).
- New: crypto test vectors (Wycheproof, RFC 9106), fuzz targets, cargo-deny policy, Security,
  CodeQL, Scorecard, Assurance and Release workflows, threat model, OWASP ASVS self-assessment,
  `unsafe` review, and a public assurance report.

## 0.1.0 — 2026-10-15

First public release.

- Encrypted local vault: Argon2id-wrapped key slots (password, recovery code, Touch ID device key),
  XChaCha20-Poly1305 for the library, hash-chained encrypted audit log, rollback detection.
- Agent with sessions, idle lock, approvals (Touch ID, authenticator code or password), and a
  policy that keeps AI clients from reading values.
- Projects, channels (inherit/protected) and global secrets; sealed, one-way and plain protection;
  file secrets.
- Integration rail: Fly.io, Vercel, GitHub Actions, `.env` files, file drops and commands, with
  delegated connections and a logged record of every push. Warnings when a one-way secret sits where
  a destination expects to push it.
- Import from `.env`/JSON/YAML files and from a folder of them; `pit scan` finds secrets in a project
  without changing it.
- Backups after every change to folders (iCloud), SSH, rclone (Google Drive and others) and S3,
  with retries until each target is current; list, diff and restore from any target.
- Bundles for moving projects between vaults; `pit seal` for any file.
- CLI, interactive console and MCP server.
