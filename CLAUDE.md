# Working on The Pit (for AI assistants and contributors)

This repository is the source of The Pit, a local encrypted secrets vault. To *use* The Pit from
another project, read [docs/for-machines.md](docs/for-machines.md) instead.

## Layout

| Path | What |
| --- | --- |
| `src/crypto.rs` | primitives: Argon2id, XChaCha20-Poly1305, HKDF, HMAC fingerprints. Wrappers over RustCrypto only. |
| `src/vault.rs` | on-disk vault: header with key slots, sealed library, history, destroy |
| `src/model.rs` | the library document: projects, channels, secrets, destinations, connections, settings |
| `src/values.rs` | storing/opening one secret value (sealed / hashed / plain) |
| `src/agent.rs` | the agent process: socket server, sessions, unlock, the approval gate |
| `src/ops.rs` | every operation, and `needs_approval` — the policy table |
| `src/protocol.rs` | client ↔ agent JSON-lines protocol |
| `src/rail/` | integration adapters: fly, vercel, github, local (dotenv/files), command |
| `src/backup.rs`, `src/s3.rs` | snapshots, bundles, backup targets |
| `src/share.rs` | sharing one secret with another vault: receive requests and shares (windows live in `agent::Session::inbox`) |
| `src/importer.rs` | importing a folder laid out `project/environment/*.env` |
| `src/scan.rs` | reading .env/JSON/YAML files for `pit import env`, and `pit scan`'s read-only detectors |
| `src/cli.rs`, `src/console.rs`, `src/mcp.rs` | the three front ends |
| `examples/folder-import.map.toml` | example map for `pit import secret-pit` |
| `tests/e2e.py`, `tests/fakes/` | end-to-end suite (throwaway `PIT_HOME`); stand-in ssh/scp/rclone |

## Rules for changes

- Never add a code path that returns or logs a secret value to an MCP client, or that bypasses
  `ops::needs_approval`. New operations go in `ops::dispatch` *and* get a line in the policy table.
- No secret in argv, URLs, environment of child processes other than the intended one, or logs.
  Values travel on stdin or in request bodies, and live in `Zeroizing` buffers.
- No new cryptographic primitives. Compose the existing ones; bind context with AAD.
- A secret a destination pushes must stay decryptable: `ops::guard_one_way` asks before a `hashed`
  secret lands where a destination expects it. Keep that check on any new path that writes secrets.
- Comments describe what code does and why it is shaped that way — not how it could be attacked.
- Every file write under `$PIT_HOME` goes through `paths::write_private` (atomic, 0600).

## Testing

```sh
cargo test                         # unit tests (crypto, shamir, totp, codes, importer, password policy)
cargo build && python tests/e2e.py # end-to-end against a throwaway PIT_HOME (needs pexpect)
scripts/gen-commands-doc           # after changing the CLI
```

Always test against a scratch vault: `PIT_HOME=$(mktemp -d) pit init`. Never point tests at `~/.the-pit`.
