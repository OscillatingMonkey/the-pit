# Changelog

## 0.1.0 — unreleased

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
