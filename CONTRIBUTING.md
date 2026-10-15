# Contributing

Thanks for helping. A few things matter more here than in most projects, because The Pit holds secrets.

## Ground rules

- **No code path may return or log a secret value** to an AI (MCP) client, a log, an error message,
  a URL, a command line, or the environment of a process other than the one it is meant for.
- **New operations go through the agent's policy.** Add them to `ops::dispatch` and give them a line in
  `ops::needs_approval` (and `AI_REFUSED` if an AI client must never run them).
- **No new cryptographic primitives.** Compose the existing ones in `src/crypto.rs`; bind context with
  associated data.
- **Comments say what code does and why**, not how it could be attacked.
- Keep pushed secrets decryptable: anything that writes secrets keeps the `ops::guard_one_way` check.

[AGENTS.md](AGENTS.md) has a map of the source.

## Building and testing

```sh
cargo build
cargo test                                   # unit tests
pip install pexpect
cargo build --release && PIT_BIN=target/release/pit python3 tests/e2e.py
```

The end-to-end suite creates a throwaway vault in a temporary `PIT_HOME`; it never touches
`~/.the-pit`. It runs on macOS and needs no Touch ID.

Before sending a pull request:

```sh
cargo fmt
cargo clippy --release -- -D warnings
PIT=target/release/pit scripts/gen-commands-doc     # if you changed a command or its help
```

## Reporting bugs

Open an issue with `pit --version`, your platform, what you ran and what happened. **Never paste a
secret value**; names and fingerprints (`pit ls`) are enough. Security problems go through
[SECURITY.md](SECURITY.md) instead.
