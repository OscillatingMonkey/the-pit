# Changelog

## Unreleased

- License: AGPL-3.0-only, with a commercial license available for closed-source or hosted use
  ([COMMERCIAL.md](COMMERCIAL.md)). Contributions are accepted under the contributor agreement in
  [CLA.md](CLA.md). Versions up to 0.1.1 stay MIT.
- Channels nest, as deep as you like: `pit channel add myapp/production/eu/fra` (missing channels
  above it are created). A channel sees its own secrets, then those of each channel above it up to
  the project, the nearest one winning; `--no-inherit` cuts that chain. Channels inside a protected
  channel are protected. `pit ls` shows the tree; renaming moves what is inside; removing a channel
  that holds others needs `--recursive`. Existing vaults, backups and bundles need no change.
- Completion everywhere: Tab in the console and in zsh, bash and fish (`pit completions SHELL`)
  completes commands, flags, flag values and names from the vault, each with a description; the
  console shows a greyed hint of the rest of the word or what comes next. Every option now has help
  text.
- Names `.` and `..` are refused for projects and channels.
- Share a secret with someone else's vault: they run `pit receive`, you run
  `pit share PROJECT/CHANNEL NAME --to PIT-RQ-…`, they save it with `pit receive PIT-SH-… --into …`.
  The value is encrypted end to end and neither person sees it; a share opens only in the recipient's
  vault, once, while their receive window is open (15 minutes by default; locking closes it). Sharing
  always asks for approval; the first exchange with someone asks you to compare identity keys
  (`pit contacts`). See [docs/sharing.md](docs/sharing.md).
- Fewer approval prompts: one approval covers more changes to the same channel or project from the
  same terminal tab (or app) for 5 minutes (`pit settings approval_window_secs`, 0 to turn off).
  Reveals, `pit run`, removals, exports and settings still ask every time, and AI clients always ask.
- A push preview (`--dry-run`, and the preview `pit push` shows before asking) no longer needs
  approval, so a push to a protected channel asks once instead of twice.
- On Linux, `pit log` now names the program that ran `pit`.

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
